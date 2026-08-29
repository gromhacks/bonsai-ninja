//! A logging-context consumer has an implicit value rather than a tainted call
//! argument. The producer/rewrite/consumer chain must therefore be proven from
//! exact compiler facts, including the negative control-character near miss.

use bonsai_security::{FindingStatus, Rulepack, TaintAnalysisOptions, TaintAnalysisReport};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn rulepack() -> &'static Rulepack {
    static PACK: OnceLock<Rulepack> = OnceLock::new();
    PACK.get_or_init(|| bonsai_security::load_rulepack(&rules_root()).expect("load rulepack"))
}

fn analyze(pattern: Option<&str>) -> TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    let (pattern_decl, write) = pattern.map_or_else(
        || (String::new(), "MDC.put(\"rid\", rid);".to_string()),
        |pattern| {
            (
                format!("private static final Pattern CONTROL = Pattern.compile(\"{pattern}\");"),
                "MDC.put(\"rid\", CONTROL.matcher(rid).replaceAll(\"_\"));".to_string(),
            )
        },
    );
    workspace.vfs().write(
        "src/Audit.java",
        Arc::<str>::from(format!(
            r#"import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

class Audit {{
  private static final Logger LOG = LoggerFactory.getLogger(Audit.class);
  {pattern_decl}
  @PostMapping("/audit")
  void event(@RequestHeader String rid) {{
    if (rid != null) {{ {write} }}
    LOG.info("audit event recorded");
  }}
}}
"#
        )),
    );
    bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        TaintAnalysisOptions {
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("Java MDC context taint analysis")
}

fn unsanitized_context_consumers(report: &TaintAnalysisReport) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| {
            finding.finding.sink.rule_id == "java.log_injection.mdc_context_logger_info"
                && finding.finding.status == FindingStatus::Unsanitized
        })
        .count()
}

#[test]
fn exact_control_character_rewrite_clears_the_implicit_context_before_logging() {
    let unsafe_report = analyze(None);
    assert_eq!(
        unsanitized_context_consumers(&unsafe_report),
        1,
        "{unsafe_report:#?}"
    );

    let safe_report = analyze(Some(r"\\p{Cntrl}"));
    assert_eq!(unsanitized_context_consumers(&safe_report), 0, "{safe_report:#?}");

    let incomplete_report = analyze(Some("[A-Z]"));
    assert_eq!(
        unsanitized_context_consumers(&incomplete_report),
        1,
        "a substitution that leaves CR/LF intact must not clear the context: {incomplete_report:#?}"
    );
}
