//! Ruby controller-source and cross-file sink composition coverage.
//!
//! Framework/API vocabulary stays in the live rulepack. These fixtures prove
//! that adapter-owned class ancestry and value flow select the intended rules
//! while same-spelled local code and literal-only endpoint arguments remain
//! quiet.

use bonsai_security::{load_rulepack, run_taint_analysis, Rulepack};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn rulepack() -> &'static Rulepack {
    static PACK: OnceLock<Rulepack> = OnceLock::new();
    PACK.get_or_init(|| load_rulepack(&rules_root()).expect("load live rulepack"))
}

fn workspace(files: &[(&str, &str)]) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    for (path, source) in files {
        ws.vfs().write(*path, *source);
    }
    ws
}

#[test]
fn controller_params_require_exact_compiler_owned_class_context() {
    let ws = workspace(&[
        (
            "application_controller.rb",
            "class ApplicationController < ActionController::Base\nend\n",
        ),
        (
            "controllers.rb",
            r#"
class ReportsController < ApplicationController
  def show
    params[:query]
  end
end

class LocalController < ApplicationBase
  def show
    params[:query]
  end
end

def helper(params)
  params[:query]
end
"#,
        ),
    ]);

    let sources =
        bonsai_security::source_inventory(&ws, rulepack(), Default::default()).expect("source inventory");
    let matches = sources
        .iter()
        .filter(|source| source.rule_id == "ruby.source.params_read")
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "only params in the exact compiler-owned controller hierarchy may be remote input: {matches:#?}"
    );
    assert_eq!(matches[0].enclosing_fn.as_deref(), Some("show"));
}

#[test]
fn controller_params_reach_cross_file_ruby_sinks_and_literal_paths_stay_quiet() {
    let ws = workspace(&[
        (
            "application_controller.rb",
            "class ApplicationController < ActionController::Base\nend\n",
        ),
        (
            "reports_controller.rb",
            r#"
class ReportsController < ApplicationController
  def restore
    PayloadOperations.unsafe_restore(params[:payload])
    PayloadOperations.safe_restore(params[:payload])
  end

  def execute
    CommandOperations.unsafe_execute(params[:command])
    CommandOperations.safe_execute(params[:command])
  end

  def read
    FileOperations.unsafe_read(params[:path])
    FileOperations.safe_read(params[:path])
  end

  def sort
    RecordOperations.unsafe_sort(params[:sort])
    RecordOperations.safe_sort(params[:sort])
  end

  def fetch
    NetworkOperations.unsafe_fetch(params[:url])
    NetworkOperations.safe_fetch(params[:url])
  end

  def render_markup
    MarkupOperations.unsafe_markup(params[:body])
    MarkupOperations.safe_markup(params[:body])
  end

  def parse_xml
    XmlOperations.unsafe_parse(params[:xml])
    XmlOperations.safe_parse(params[:xml])
  end
end
"#,
        ),
        (
            "payload_operations.rb",
            r#"
class PayloadOperations
  def self.unsafe_restore(value)
    Marshal.load(value)
  end

  def self.safe_restore(_value)
    Marshal.load("\x04\b0")
  end
end
"#,
        ),
        (
            "command_operations.rb",
            r#"
class CommandOperations
  def self.unsafe_execute(value)
    `#{value}`
  end

  def self.safe_execute(_value)
    `whoami`
  end
end
"#,
        ),
        (
            "file_operations.rb",
            r#"
class FileOperations
  def self.unsafe_read(value)
    File.binread(value)
  end

  def self.safe_read(_value)
    File.binread("config/banner.bin")
  end
end
"#,
        ),
        (
            "record_operations.rb",
            r#"
class RecordOperations
  def self.unsafe_sort(value)
    Account.order(value)
  end

  def self.safe_sort(_value)
    Account.order("created_at DESC")
  end
end
"#,
        ),
        (
            "network_operations.rb",
            r#"
class NetworkOperations
  def self.unsafe_fetch(value)
    Net::HTTP.get(value)
  end

  def self.safe_fetch(_value)
    Net::HTTP.get("https://example.com/health")
  end
end
"#,
        ),
        (
            "markup_operations.rb",
            r#"
require "actionview"
class MarkupOperations
  def self.unsafe_markup(value)
    raw(value)
  end

  def self.safe_markup(_value)
    raw("<p>ready</p>")
  end
end
"#,
        ),
        (
            "xml_operations.rb",
            r#"
require "nokogiri"
class XmlOperations
  def self.unsafe_parse(value)
    Nokogiri.XML(value, nil, nil, Nokogiri::XML::ParseOptions::NOENT)
  end

  def self.safe_parse(value)
    Nokogiri.XML(value, nil, nil, Nokogiri::XML::ParseOptions::NONET)
  end
end
"#,
        ),
    ]);

    let report = run_taint_analysis(&ws, rulepack(), Default::default()).expect("Ruby taint analysis");
    let expected = [
        ("ruby.deser.marshal_load_call", "unsafe_restore", "safe_restore"),
        ("ruby.cmdi.kernel_backtick", "unsafe_execute", "safe_execute"),
        ("ruby.path.file_binread", "unsafe_read", "safe_read"),
        ("ruby.sqli.ar_order", "unsafe_sort", "safe_sort"),
        ("ruby.ssrf.net_http_get", "unsafe_fetch", "safe_fetch"),
        ("ruby.xss.raw", "unsafe_markup", "safe_markup"),
        ("ruby.xxe.nokogiri_xml", "unsafe_parse", "safe_parse"),
    ];

    for (sink_rule, unsafe_method, safe_method) in expected {
        assert!(
            report.findings.iter().any(|finding| {
                finding.finding.source.rule_id == "ruby.source.params_read"
                    && finding.finding.sink.rule_id == sink_rule
                    && finding.finding.sink.enclosing_fn.as_deref() == Some(unsafe_method)
            }),
            "missing exact params-to-{sink_rule} cross-file flow in {unsafe_method}: {:#?}",
            report.findings
        );
        assert!(
            report.findings.iter().all(|finding| {
                finding.finding.sink.rule_id != sink_rule
                    || finding.finding.sink.enclosing_fn.as_deref() != Some(safe_method)
            }),
            "literal-only endpoint {safe_method} must not report {sink_rule}: {:#?}",
            report.findings
        );
    }
}
