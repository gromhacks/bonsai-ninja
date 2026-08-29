//! Cross-language path-containment proofs for runtimes whose canonical path
//! APIs are expressed as functions, receiver chains, properties, or result
//! matches. Every safe fixture is paired with a proof-breaking variant so a
//! textual prefix check cannot accidentally acquire sanitizer credit.

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

fn analyze(path: &str, source: &str) -> TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write(path, Arc::<str>::from(source));
    bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        TaintAnalysisOptions {
            include_inferred_sources: true,
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("taint analysis")
}

fn status(report: &TaintAnalysisReport, rule: &str, function: &str) -> FindingStatus {
    report
        .findings
        .iter()
        .find(|finding| {
            finding.finding.sink.rule_id == rule
                && finding.finding.sink.enclosing_fn.as_deref() == Some(function)
        })
        .unwrap_or_else(|| panic!("missing {rule} in {function}: {:#?}", report.findings))
        .finding
        .status
}

#[test]
fn perl_function_path_proof_requires_static_root_boundary_and_accepting_result() {
    let report = analyze(
        "Store.pm",
        r#"
use Cwd qw(abs_path);
use File::Spec;
use constant ROOT => '/srv/assets';
sub safe {
    my ($name) = @_;
    my $root = abs_path(ROOT) or return undef;
    my $path = abs_path(File::Spec->catfile($root, $name)) or return undef;
    return undef unless index($path, "$root/") == 0;
    open(my $fh, '<', $path);
}
sub dynamic_root {
    my ($root_input, $name) = @_;
    my $root = abs_path($root_input) or return undef;
    my $path = abs_path(File::Spec->catfile($root, $name)) or return undef;
    return undef unless index($path, "$root/") == 0;
    open(my $fh, '<', $path);
}
sub missing_boundary {
    my ($name) = @_;
    my $root = abs_path(ROOT) or return undef;
    my $path = abs_path(File::Spec->catfile($root, $name)) or return undef;
    return undef unless index($path, $root) == 0;
    open(my $fh, '<', $path);
}
"#,
    );
    assert_eq!(
        status(&report, "perl.path.open_read", "safe"),
        FindingStatus::Sanitized
    );
    assert_eq!(
        status(&report, "perl.path.open_read", "dynamic_root"),
        FindingStatus::Unsanitized
    );
    assert_eq!(
        status(&report, "perl.path.open_read", "missing_boundary"),
        FindingStatus::Unsanitized
    );
}

#[test]
fn ruby_receiver_path_proof_requires_static_root_boundary_and_rejection() {
    let report = analyze(
        "store.rb",
        r##"
class Store
  # Immutable class constant whose value remains the literal receiver of freeze.
  ROOT = "/srv/assets".freeze
  def self.safe(name)
    root = File.expand_path(ROOT)
    path = File.expand_path(File.join(root, name))
    raise ArgumentError unless path.start_with?("#{root}/")
    File.binread(path)
  end
  def self.dynamic_root(root_input, name)
    root = File.expand_path(root_input)
    path = File.expand_path(File.join(root, name))
    raise ArgumentError unless path.start_with?("#{root}/")
    File.binread(path)
  end
  def self.missing_boundary(name)
    root = File.expand_path(ROOT)
    path = File.expand_path(File.join(root, name))
    raise ArgumentError unless path.start_with?(root)
    File.binread(path)
  end
end
"##,
    );
    assert_eq!(
        status(&report, "ruby.path.file_binread", "safe"),
        FindingStatus::Sanitized
    );
    assert_eq!(
        status(&report, "ruby.path.file_binread", "dynamic_root"),
        FindingStatus::Unsanitized
    );
    assert_eq!(
        status(&report, "ruby.path.file_binread", "missing_boundary"),
        FindingStatus::Unsanitized
    );
}

#[test]
fn ruby_block_forwarded_static_root_is_proven_but_dynamic_root_is_not() {
    let report = analyze(
        "asset_store.rb",
        r##"
class AssetStore
  ROOT = "/srv/assets".freeze
  def self.with_root
    yield ROOT
  end
  def self.safe_read(root, name)
    canonical_root = File.expand_path(root)
    target = File.expand_path(File.join(canonical_root, name))
    raise ArgumentError unless target.start_with?("#{canonical_root}/")
    File.binread(target)
  end
  def self.dynamic_read(root, name)
    canonical_root = File.expand_path(root)
    target = File.expand_path(File.join(canonical_root, name))
    raise ArgumentError unless target.start_with?("#{canonical_root}/")
    File.binread(target)
  end
end
def safe_endpoint(name)
  AssetStore.with_root { |root| AssetStore.safe_read(root, name) }
end
def dynamic_endpoint(configured_root, name)
  AssetStore.dynamic_read(configured_root, name)
end
"##,
    );
    assert_eq!(
        status(&report, "ruby.path.file_binread", "safe_read"),
        FindingStatus::Sanitized,
        "exact yield/callback and call-argument facts preserve static-root provenance: {:#?}",
        report.findings
    );
    assert_eq!(
        status(&report, "ruby.path.file_binread", "dynamic_read"),
        FindingStatus::Unsanitized,
        "a caller-supplied root must fail closed: {:#?}",
        report.findings
    );
}

#[test]
fn php_composed_path_proof_requires_static_root_boundary_and_rejection() {
    let report = analyze(
        "AssetStore.php",
        r#"
<?php
final class AssetStore {
  private const ROOT = '/srv/assets';
  public static function safe(string $name): string {
    $root = realpath(self::ROOT);
    $path = realpath(self::ROOT . '/' . $name);
    if ($root === false || $path === false || !str_starts_with($path, $root . '/')) {
      throw new RuntimeException('escape');
    }
    return (string) file_get_contents($path);
  }
  public static function dynamicRoot(string $configuredRoot, string $name): string {
    $root = realpath($configuredRoot);
    $path = realpath($configuredRoot . '/' . $name);
    if ($root === false || $path === false || !str_starts_with($path, $root . '/')) {
      throw new RuntimeException('escape');
    }
    return (string) file_get_contents($path);
  }
  public static function missingBoundary(string $name): string {
    $root = realpath(self::ROOT);
    $path = realpath(self::ROOT . '/' . $name);
    if ($root === false || $path === false || !str_starts_with($path, $root)) {
      throw new RuntimeException('escape');
    }
    return (string) file_get_contents($path);
  }
}
"#,
    );
    assert_eq!(
        status(&report, "php.path.file_get_contents", "safe"),
        FindingStatus::Sanitized,
        "ordered compiler composition plus exact rejection must receive credit: {:#?}",
        report.findings
    );
    assert_eq!(
        status(&report, "php.path.file_get_contents", "dynamicRoot"),
        FindingStatus::Unsanitized,
        "a dynamic root must fail closed: {:#?}",
        report.findings
    );
    assert_eq!(
        status(&report, "php.path.file_get_contents", "missingBoundary"),
        FindingStatus::Unsanitized,
        "a textual prefix without a segment boundary must fail closed: {:#?}",
        report.findings
    );
}

#[test]
fn rust_result_path_proof_requires_static_root_and_rejecting_branch() {
    let report = analyze(
        "store.rs",
        r#"
use std::fs;
use std::path::PathBuf;
const ROOT: &str = "/srv/assets";
fn safe(name: &str) -> Vec<u8> {
    let root = match fs::canonicalize(ROOT) { Ok(value) => value, Err(_) => return Vec::new() };
    let path = match fs::canonicalize(PathBuf::from(ROOT).join(name)) { Ok(value) => value, Err(_) => return Vec::new() };
    if !path.starts_with(&root) { return Vec::new(); }
    fs::read(&path).unwrap_or_default()
}
fn dynamic_root(root_input: &str, name: &str) -> Vec<u8> {
    let root = match fs::canonicalize(root_input) { Ok(value) => value, Err(_) => return Vec::new() };
    let path = match fs::canonicalize(PathBuf::from(root_input).join(name)) { Ok(value) => value, Err(_) => return Vec::new() };
    if !path.starts_with(&root) { return Vec::new(); }
    fs::read(&path).unwrap_or_default()
}
fn wrong_branch(name: &str) -> Vec<u8> {
    let root = match fs::canonicalize(ROOT) { Ok(value) => value, Err(_) => return Vec::new() };
    let path = match fs::canonicalize(PathBuf::from(ROOT).join(name)) { Ok(value) => value, Err(_) => return Vec::new() };
    if path.starts_with(&root) { return Vec::new(); }
    fs::read(&path).unwrap_or_default()
}
"#,
    );
    assert_eq!(
        status(&report, "rust.path.fs_read", "safe"),
        FindingStatus::Sanitized
    );
    assert_eq!(
        status(&report, "rust.path.fs_read", "dynamic_root"),
        FindingStatus::Unsanitized
    );
    assert_eq!(
        status(&report, "rust.path.fs_read", "wrong_branch"),
        FindingStatus::Unsanitized
    );
}

#[test]
fn scala_receiver_path_proof_requires_static_root_and_rejecting_branch() {
    let report = analyze(
        "Store.scala",
        r#"
import java.nio.file.{Files, Paths}
object Store {
  private val Root = "/srv/assets"
  def safe(name: String): Array[Byte] = {
    val root = Paths.get(Root).toAbsolutePath.normalize
    val path = root.resolve(name).normalize
    if (!path.startsWith(root)) Array.emptyByteArray
    else Files.readAllBytes(path)
  }
  def dynamicRoot(rootInput: String, name: String): Array[Byte] = {
    val root = Paths.get(rootInput).toAbsolutePath.normalize
    val path = root.resolve(name).normalize
    if (!path.startsWith(root)) Array.emptyByteArray
    else Files.readAllBytes(path)
  }
  def wrongBranch(name: String): Array[Byte] = {
    val root = Paths.get(Root).toAbsolutePath.normalize
    val path = root.resolve(name).normalize
    if (path.startsWith(root)) Array.emptyByteArray
    else Files.readAllBytes(path)
  }
}
"#,
    );
    assert_eq!(
        status(&report, "scala.path.files_readallbytes", "safe"),
        FindingStatus::Sanitized
    );
    assert_eq!(
        status(&report, "scala.path.files_readallbytes", "dynamicRoot"),
        FindingStatus::Unsanitized
    );
    assert_eq!(
        status(&report, "scala.path.files_readallbytes", "wrongBranch"),
        FindingStatus::Unsanitized
    );
}

#[test]
fn swift_property_path_proof_requires_static_root_boundary_and_rejection() {
    let report = analyze(
        "Store.swift",
        r#"
import Foundation
struct Store {
    private let base = URL(fileURLWithPath: "/srv/assets")
    func safe(name: String) -> Data {
        let root = base.standardizedFileURL
        let target = root.appendingPathComponent(name).standardizedFileURL
        guard target.path.hasPrefix(root.path + "/") else { return Data() }
        return (try? Data(contentsOf: target)) ?? Data()
    }
    func dynamicRoot(rootInput: String, name: String) -> Data {
        let root = URL(fileURLWithPath: rootInput).standardizedFileURL
        let target = root.appendingPathComponent(name).standardizedFileURL
        guard target.path.hasPrefix(root.path + "/") else { return Data() }
        return (try? Data(contentsOf: target)) ?? Data()
    }
    func missingBoundary(name: String) -> Data {
        let root = base.standardizedFileURL
        let target = root.appendingPathComponent(name).standardizedFileURL
        guard target.path.hasPrefix(root.path) else { return Data() }
        return (try? Data(contentsOf: target)) ?? Data()
    }
}
"#,
    );
    assert_eq!(
        status(&report, "swift.path.data_init_contents", "safe"),
        FindingStatus::Sanitized
    );
    assert_eq!(
        status(&report, "swift.path.data_init_contents", "dynamicRoot"),
        FindingStatus::Unsanitized
    );
    assert_eq!(
        status(&report, "swift.path.data_init_contents", "missingBoundary"),
        FindingStatus::Unsanitized
    );
}
