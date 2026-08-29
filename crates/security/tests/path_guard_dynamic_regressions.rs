//! Compiler-backed path-guard regressions for dynamic and native frontends.
//!
//! Every credited guard has nearby wrong-polarity, dynamic-root, or missing-
//! boundary variants.  These tests intentionally use ordinary runtime APIs;
//! no fixture or repository identity participates in the proof.

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

fn analyze(file: &str, source: &str) -> TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write(file, Arc::<str>::from(source));
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

fn sink_status(report: &TaintAnalysisReport, rule: &str, function: &str) -> FindingStatus {
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
fn objc_standardized_path_requires_static_root_rejection_and_segment_boundary() {
    let report = analyze(
        "AssetReader.m",
        r#"
#import <Foundation/Foundation.h>
static NSString *const FixedRoot = @"/srv/assets";

NSData *safePath(NSString *input) {
  NSString *root = [FixedRoot stringByStandardizingPath];
  NSString *path = [[root stringByAppendingPathComponent:input] stringByStandardizingPath];
  if (![path hasPrefix:[root stringByAppendingString:@"/"]]) return nil;
  return [NSData dataWithContentsOfFile:path];
}
NSData *wrongDirection(NSString *input) {
  NSString *root = [FixedRoot stringByStandardizingPath];
  NSString *path = [[root stringByAppendingPathComponent:input] stringByStandardizingPath];
  if ([path hasPrefix:[root stringByAppendingString:@"/"]]) return nil;
  return [NSData dataWithContentsOfFile:path];
}
NSData *dynamicRoot(NSString *input, NSString *configuredRoot) {
  NSString *root = [configuredRoot stringByStandardizingPath];
  NSString *path = [[root stringByAppendingPathComponent:input] stringByStandardizingPath];
  if (![path hasPrefix:[root stringByAppendingString:@"/"]]) return nil;
  return [NSData dataWithContentsOfFile:path];
}
NSData *missingBoundary(NSString *input) {
  NSString *root = [FixedRoot stringByStandardizingPath];
  NSString *path = [[root stringByAppendingPathComponent:input] stringByStandardizingPath];
  if (![path hasPrefix:root]) return nil;
  return [NSData dataWithContentsOfFile:path];
}
"#,
    );

    assert_eq!(
        sink_status(&report, "objc.path.data_with_contents_of_file", "safePath"),
        FindingStatus::Sanitized,
        "complete compiler proof must receive credit: {:#?}",
        report.findings
    );
    for function in ["wrongDirection", "dynamicRoot", "missingBoundary"] {
        assert_eq!(
            sink_status(&report, "objc.path.data_with_contents_of_file", function),
            FindingStatus::Unsanitized,
            "near-miss {function} must stay reportable: {:#?}",
            report.findings
        );
    }
}

#[test]
fn kotlin_canonical_file_precondition_requires_static_root_and_segment_boundary() {
    let report = analyze(
        "AssetReader.kt",
        r#"
import java.io.File
import kotlin.io.*

private val FixedRoot = File("/srv/assets")

fun safePath(input: String): ByteArray {
  val root = FixedRoot.canonicalFile
  val path = File(root, input).canonicalFile
  require(path.path.startsWith(root.path + File.separator))
  return path.readBytes()
}
fun wrongDirection(input: String): ByteArray {
  val root = FixedRoot.canonicalFile
  val path = File(root, input).canonicalFile
  require(!path.path.startsWith(root.path + File.separator))
  return path.readBytes()
}
fun dynamicRoot(input: String, configuredRoot: String): ByteArray {
  val root = File(configuredRoot).canonicalFile
  val path = File(root, input).canonicalFile
  require(path.path.startsWith(root.path + File.separator))
  return path.readBytes()
}
fun missingBoundary(input: String): ByteArray {
  val root = FixedRoot.canonicalFile
  val path = File(root, input).canonicalFile
  require(path.path.startsWith(root.path))
  return path.readBytes()
}
"#,
    );

    assert_eq!(
        sink_status(&report, "kotlin.path.file_readbytes", "safePath"),
        FindingStatus::Sanitized,
        "complete compiler proof must receive credit: {:#?}",
        report.findings
    );
    for function in ["wrongDirection", "dynamicRoot", "missingBoundary"] {
        assert_eq!(
            sink_status(&report, "kotlin.path.file_readbytes", function),
            FindingStatus::Unsanitized,
            "near-miss {function} must stay reportable: {:#?}",
            report.findings
        );
    }
}

#[test]
fn kotlin_class_val_root_is_visible_but_mutable_class_state_is_not_static() {
    let report = analyze(
        "AssetStore.kt",
        r#"
import java.io.File
import kotlin.io.*

class AssetStore {
  private val base = File("/srv/assets")
  fun safePath(input: String): ByteArray {
    val root = base.canonicalFile
    val path = File(root, input).canonicalFile
    require(path.path.startsWith(root.path + File.separator))
    return path.readBytes()
  }
}
class MutableStore(configuredRoot: String) {
  private var base = File(configuredRoot)
  fun dynamicRoot(input: String): ByteArray {
    val root = base.canonicalFile
    val path = File(root, input).canonicalFile
    require(path.path.startsWith(root.path + File.separator))
    return path.readBytes()
  }
}
"#,
    );

    assert_eq!(
        sink_status(&report, "kotlin.path.file_readbytes", "safePath"),
        FindingStatus::Sanitized,
        "an immutable class field with a literal factory input is exact static provenance: {:#?}",
        report.findings
    );
    assert_eq!(
        sink_status(&report, "kotlin.path.file_readbytes", "dynamicRoot"),
        FindingStatus::Unsanitized,
        "mutable/configured class state must fail closed: {:#?}",
        report.findings
    );
}

#[test]
fn scala_class_val_root_is_visible_but_mutable_class_state_is_not_static() {
    let report = analyze(
        "AssetStore.scala",
        r#"
import java.nio.file.{Files, Paths}

class AssetStore {
  private val base = "/srv/assets"
  def safePath(input: String): Array[Byte] = {
    val root = Paths.get(base).toAbsolutePath.normalize
    val path = root.resolve(input).normalize
    if (!path.startsWith(root)) Array.emptyByteArray
    else Files.readAllBytes(path)
  }
}
class MutableStore(configuredRoot: String) {
  private var base = configuredRoot
  def dynamicRoot(input: String): Array[Byte] = {
    val root = Paths.get(base).toAbsolutePath.normalize
    val path = root.resolve(input).normalize
    if (!path.startsWith(root)) Array.emptyByteArray
    else Files.readAllBytes(path)
  }
}
"#,
    );

    assert_eq!(
        sink_status(&report, "scala.path.files_readallbytes", "safePath"),
        FindingStatus::Sanitized,
        "an immutable class field with a literal value is exact static provenance: {:#?}",
        report.findings
    );
    assert_eq!(
        sink_status(&report, "scala.path.files_readallbytes", "dynamicRoot"),
        FindingStatus::Unsanitized,
        "mutable/configured class state must fail closed: {:#?}",
        report.findings
    );
}

#[test]
fn cpp_canonical_path_prefix_requires_zero_offset_static_root_and_boundary() {
    let report = analyze(
        "reader.cpp",
        r#"
#include <filesystem>
#include <fstream>
#include <string>
namespace fs = std::filesystem;
static const fs::path FixedRoot = "/srv/assets";

void safePath(const std::string &input) {
  fs::path target = fs::weakly_canonical(FixedRoot / input);
  auto root = fs::weakly_canonical(FixedRoot).string();
  if (target.string().rfind(root + "/", 0) != 0) return;
  std::ifstream stream(target, std::ios::binary);
}

void wrongDirection(const std::string &input) {
  fs::path target = fs::weakly_canonical(FixedRoot / input);
  auto root = fs::weakly_canonical(FixedRoot).string();
  if (target.string().rfind(root + "/", 0) == 0) return;
  std::ifstream stream(target, std::ios::binary);
}
void dynamicRoot(const std::string &input, const fs::path &configuredRoot) {
  fs::path target = fs::weakly_canonical(configuredRoot / input);
  auto root = fs::weakly_canonical(configuredRoot).string();
  if (target.string().rfind(root + "/", 0) != 0) return;
  std::ifstream stream(target, std::ios::binary);
}
void missingBoundary(const std::string &input) {
  fs::path target = fs::weakly_canonical(FixedRoot / input);
  auto root = fs::weakly_canonical(FixedRoot).string();
  if (target.string().rfind(root, 0) != 0) return;
  std::ifstream stream(target, std::ios::binary);
}
"#,
    );

    assert_eq!(
        sink_status(&report, "cpp.path.ifstream", "safePath"),
        FindingStatus::Sanitized,
        "complete compiler proof must receive credit: {:#?}",
        report.findings
    );
    for function in ["wrongDirection", "dynamicRoot", "missingBoundary"] {
        assert_eq!(
            sink_status(&report, "cpp.path.ifstream", function),
            FindingStatus::Unsanitized,
            "near-miss {function} must stay reportable: {:#?}",
            report.findings
        );
    }
}

#[test]
fn lua_filename_helper_requires_safe_predicate_acceptance_and_static_root() {
    let report = analyze(
        "asset_store.lua",
        r#"
local FixedRoot = "/srv/assets"

local function safe_name(value)
  return value ~= "" and value:match("^[%w%._%-]+$") ~= nil and value:find("%.%.") == nil
end
local function weak_name(value)
  return value:find("/") == nil
end

local function safePath(name)
  if not safe_name(name) then return nil end
  return io.open(FixedRoot .. "/" .. name, "rb")
end
local function wrongDirection(name)
  if safe_name(name) then return nil end
  return io.open(FixedRoot .. "/" .. name, "rb")
end
local function dynamicRoot(name, configuredRoot)
  if not safe_name(name) then return nil end
  return io.open(configuredRoot .. "/" .. name, "rb")
end
local function missingBoundary(name)
  if not weak_name(name) then return nil end
  return io.open(FixedRoot .. "/" .. name, "rb")
end
"#,
    );

    assert_eq!(
        sink_status(&report, "lua.path.io_open_read", "safePath"),
        FindingStatus::Sanitized,
        "complete compiler proof must receive credit: {:#?}",
        report.findings
    );
    for function in ["wrongDirection", "dynamicRoot", "missingBoundary"] {
        assert_eq!(
            sink_status(&report, "lua.path.io_open_read", function),
            FindingStatus::Unsanitized,
            "near-miss {function} must stay reportable: {:#?}",
            report.findings
        );
    }
}
