use bonsai_security::{FindingStatus, Rulepack, TaintAnalysisReport};
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

fn analyze(source: &str) -> TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write("app.pl", Arc::<str>::from(source));
    bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("taint analysis")
}

fn sink_status(report: &TaintAnalysisReport, sink_rule: &str) -> FindingStatus {
    report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == sink_rule)
        .unwrap_or_else(|| panic!("missing sink {sink_rule}: {:#?}", report.findings))
        .finding
        .status
}

#[test]
fn configured_xml_receiver_requires_every_exact_factory_argument() {
    let source = |expand: &str, network: &str| {
        format!(
            r#"use XML::LibXML;
my $xml = <STDIN>;
my $parser = XML::LibXML->new(
  "expand_entities", {expand},
  "load_ext_dtd", 0,
  "no_network", {network}
);
$parser->parse_string($xml);
"#,
        )
    };
    assert_eq!(
        sink_status(&analyze(&source("0", "1")), "perl.xxe.xml_libxml_parse_string"),
        FindingStatus::Sanitized
    );
    for unsafe_source in [source("1", "1"), source("0", "$runtime_flag")] {
        assert_eq!(
            sink_status(&analyze(&unsafe_source), "perl.xxe.xml_libxml_parse_string"),
            FindingStatus::Unsanitized,
            "incomplete or dynamic parser configuration must retain the finding"
        );
    }
}

#[test]
fn path_consumer_requires_static_base_boundary_and_accepted_result() {
    let source = |root: &str, boundary: &str, relation: &str| {
        format!(
            r#"use Cwd qw(abs_path);
use File::Spec;
sub handle {{
  my ($name) = @_;
  my $root = abs_path({root});
  my $path = abs_path(File::Spec->catfile($root, $name));
  if (index($path, {boundary}) {relation} 0) {{
    open(my $fh, '<', $path);
  }} else {{
    die 'outside root';
  }}
}}
"#,
        )
    };

    assert_eq!(
        sink_status(
            &analyze(&source("\"/srv/data\"", "$root . \"/\"", "==")),
            "perl.path.open_read",
        ),
        FindingStatus::Sanitized,
        "an exact canonical base, segment boundary, and accepted index result must receive guard credit",
    );

    for unsafe_source in [
        source("$name", "$root . \"/\"", "=="),
        source("\"/srv/data\"", "$root", "=="),
        source("\"/srv/data\"", "$root . \"/\"", "!="),
    ] {
        assert_eq!(
            sink_status(&analyze(&unsafe_source), "perl.path.open_read"),
            FindingStatus::Unsanitized,
            "a dynamic base, missing boundary, or rejecting comparison must retain the finding",
        );
    }
}
