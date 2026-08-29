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
fn lua_terminal_full_alphabet_helper_sanitizes_shell_interpolation_only() {
    let safe = analyze(
        "safe.lua",
        r#"local function host_ok(value)
  return value ~= "" and value:match("^[%w%.%-]+$") ~= nil
end

local function run()
  local host = io.read()
  if not host_ok(host) then return end
  os.execute("ping -c 1 " .. host)
end
"#,
    );
    assert_eq!(
        sink_status(&safe, "lua.cmdi.os_execute"),
        FindingStatus::Sanitized,
        "{safe:#?}"
    );

    for source in [
        r#"local function host_ok(value)
  return value ~= "" and value:match("^[%w%.%-]+$") ~= nil
end
local function run()
  local host = io.read()
  local observed = host_ok(host)
  os.execute("ping -c 1 " .. host)
  return observed
end
"#,
        r#"local function host_ok(value)
  return value:match("^.*$") ~= nil
end
local function run()
  local host = io.read()
  if not host_ok(host) then return end
  os.execute("ping -c 1 " .. host)
end
"#,
    ] {
        let report = analyze("unsafe.lua", source);
        assert_eq!(
            sink_status(&report, "lua.cmdi.os_execute"),
            FindingStatus::Unsanitized,
            "an observed or permissive predicate must not sanitize shell input: {report:#?}"
        );
    }
}

#[test]
fn lua_finite_host_helper_credits_only_terminal_guard_and_disabled_redirects() {
    let source = |guard: &str, redirect: &str| {
        format!(
            r#"local http = require "resty.http"
local ALLOWED = {{ ["api.example"] = true, ["hooks.example"] = true }}
local function allowed(value)
  local host = value:match("^https://([^/]+)")
  return host ~= nil and ALLOWED[host] == true
end
local function run()
  local args = ngx.req.get_uri_args()
  local target = args.url
  {guard}
  local client = http.new()
  return client:request_uri(target, {{ method = "GET", redirect = {redirect} }})
end
"#
        )
    };
    let safe = analyze(
        "fetch.lua",
        &source("if not allowed(target) then return \"\" end", "false"),
    );
    assert_eq!(
        sink_status(&safe, "lua.ssrf.luaresty_http_request_uri"),
        FindingStatus::Sanitized,
        "{safe:#?}"
    );

    for unsafe_source in [
        source("local observed = allowed(target)", "false"),
        source("if not allowed(target) then return \"\" end", "true"),
    ] {
        let report = analyze("fetch.lua", &unsafe_source);
        assert_eq!(
            sink_status(&report, "lua.ssrf.luaresty_http_request_uri"),
            FindingStatus::Unsanitized,
            "observation without rejection or enabled redirects must fail closed: {report:#?}"
        );
    }
}

#[test]
fn lua_doctype_search_requires_a_terminal_rejection_before_xml_parse() {
    let safe = analyze(
        "safe.lua",
        r#"local lxp = require "lxp"
local function parse()
  local xml = io.read()
  if xml:find("<!DOCTYPE", 1, true) or xml:find("<!ENTITY", 1, true) then
    return
  end
  local parser = lxp.new({})
  parser:parse(xml)
end
"#,
    );
    assert_eq!(
        sink_status(&safe, "lua.xxe.lxp_parse"),
        FindingStatus::Sanitized,
        "{safe:#?}"
    );

    let observed = analyze(
        "unsafe.lua",
        r#"local lxp = require "lxp"
local function parse()
  local xml = io.read()
  local seen = xml:find("<!DOCTYPE", 1, true)
  local parser = lxp.new({})
  parser:parse(xml)
  return seen
end
"#,
    );
    assert_eq!(
        sink_status(&observed, "lua.xxe.lxp_parse"),
        FindingStatus::Unsanitized,
        "observing a declaration marker without rejecting it must preserve the finding: {observed:#?}"
    );
}

#[test]
fn elixir_finite_module_map_selection_is_exact_and_fail_closed() {
    let safe = analyze(
        "safe.ex",
        r#"alias Postgrex
defmodule Safe do
  @choices %{"first" => "alpha", "second" => "beta"}
  def run do
    key = IO.gets("> ")
    selected = Map.get(@choices, key, "fallback")
    Postgrex.query!(conn(), selected, [])
  end
end
"#,
    );
    assert_eq!(
        sink_status(&safe, "elixir.sqli.postgrex_query_bang"),
        FindingStatus::Sanitized,
        "{safe:#?}"
    );

    for source in [
        r#"alias Postgrex
defmodule DynamicValue do
  @choices %{"first" => runtime_value()}
  def run do
    key = IO.gets("> ")
    selected = Map.get(@choices, key, "fallback")
    Postgrex.query!(conn(), selected, [])
  end
end
"#,
        r#"alias Postgrex
defmodule WrongRole do
  @choices %{"first" => "alpha"}
  def run do
    key = IO.gets("> ")
    selected = Map.get(key, @choices, "fallback")
    Postgrex.query!(conn(), selected, [])
  end
end
"#,
    ] {
        let report = analyze("unsafe.ex", source);
        assert_eq!(
            sink_status(&report, "elixir.sqli.postgrex_query_bang"),
            FindingStatus::Unsanitized,
            "near-miss selector must retain the finding"
        );
    }
}

#[test]
fn beam_xml_options_require_the_exact_safe_field_value() {
    for (file, safe_source, unsafe_source, sink) in [
        (
            "parser.ex",
            r#"defmodule Parser do
  def run do
    xml = IO.gets("> ")
    :xmerl_scan.string(xml, allow_entities: false)
  end
end
"#,
            r#"defmodule Parser do
  def run do
    xml = IO.gets("> ")
    :xmerl_scan.string(xml, allow_entities: true)
  end
end
"#,
            "elixir.xxe.xmerl_scan_string",
        ),
        (
            "parser.erl",
            "-module(parser).\n-export([run/1]).\nrun(Req) -> Xml = cowboy_req:qs(Req), xmerl_scan:string(Xml, [{allow_entities, false}]).\n",
            "-module(parser).\n-export([run/1]).\nrun(Req) -> Xml = cowboy_req:qs(Req), xmerl_scan:string(Xml, [{allow_entities, true}]).\n",
            "erlang.xxe.xmerl_scan_string",
        ),
    ] {
        assert_eq!(
            sink_status(&analyze(file, safe_source), sink),
            FindingStatus::Sanitized,
            "exact disabled-entity option should be credited"
        );
        assert_eq!(
            sink_status(&analyze(file, unsafe_source), sink),
            FindingStatus::Unsanitized,
            "enabled entities must preserve the finding"
        );
    }
}

#[test]
fn elixir_canonical_path_safe_arm_requires_exact_polarity() {
    let source = |condition: &str, rejection: &str| {
        format!(
            r#"defmodule Store do
  @base "/srv/assets"
  def read do
    name = IO.gets("> ")
    root = Path.expand(@base)
    path = Path.expand(Path.join(root, name))
    if {condition} do
      File.read!(path)
    else
      {rejection}
    end
  end
end
"#
        )
    };
    let safe = analyze(
        "store.ex",
        &source(
            "String.starts_with?(path, root <> \"/\")",
            "raise \"outside root\"",
        ),
    );
    assert_eq!(
        sink_status(&safe, "elixir.path.file_read_bang"),
        FindingStatus::Sanitized,
        "{safe:#?}"
    );

    let opposite = source(
        "not String.starts_with?(path, root <> \"/\")",
        "raise \"outside root\"",
    );
    assert_eq!(
        sink_status(&analyze("store.ex", &opposite), "elixir.path.file_read_bang"),
        FindingStatus::Unsanitized
    );

    // The sink exists only in the compiler-proven accepting arm. The other
    // arm need not throw because it cannot reach the sink.
    let non_abrupt_else = source("String.starts_with?(path, root <> \"/\")", ":ok");
    assert_eq!(
        sink_status(
            &analyze("store.ex", &non_abrupt_else),
            "elixir.path.file_read_bang"
        ),
        FindingStatus::Sanitized
    );
}

#[test]
fn erlang_canonical_path_safe_arm_requires_exact_polarity() {
    let source = |condition: &str, rejection: &str| {
        format!(
            "-module(store).\n-define(BASE, \"/srv/assets\").\n-export([read/1]).\nread(Req) ->\n  Name = cowboy_req:path(Req),\n  Path = filename:absname(filename:join(?BASE, Name)),\n  Root = filename:absname(?BASE) ++ \"/\",\n  case {condition} of\n    true -> file:read_file(Path);\n    false -> {rejection}\n  end.\n"
        )
    };
    let safe = analyze(
        "store.erl",
        &source("lists:prefix(Root, Path)", "erlang:error(outside_root)"),
    );
    assert_eq!(
        sink_status(&safe, "erlang.path.file_read_file"),
        FindingStatus::Sanitized,
        "{safe:#?}"
    );
    let opposite = source("not lists:prefix(Root, Path)", "erlang:error(outside_root)");
    assert_eq!(
        sink_status(&analyze("store.erl", &opposite), "erlang.path.file_read_file"),
        FindingStatus::Unsanitized,
        "opposite containment polarity must retain the finding:\n{opposite}"
    );

    // As in Elixir, the sink is branch-local. A non-abrupt alternate arm is
    // safe because that arm has no path to the sink.
    let non_abrupt_else = source("lists:prefix(Root, Path)", "ok");
    assert_eq!(
        sink_status(
            &analyze("store.erl", &non_abrupt_else),
            "erlang.path.file_read_file"
        ),
        FindingStatus::Sanitized
    );
}

#[test]
fn erlang_canonical_path_accepts_a_stricter_conjunctive_guard() {
    let safe = analyze(
        "store.erl",
        r#"-module(store).
-define(BASE, "/srv/assets").
-export([read/1]).
read(Req) ->
  Name = cowboy_req:path(Req),
  N = binary_to_list(Name),
  Path = filename:absname(filename:join(?BASE, N)),
  Root = filename:absname(?BASE) ++ "/",
  case lists:prefix(Root, Path) andalso not lists:member("..", filename:split(N)) of
    true -> file:read_file(Path);
    false -> {error, eacces}
  end.
"#,
    );
    assert_eq!(
        sink_status(&safe, "erlang.path.file_read_file"),
        FindingStatus::Sanitized,
        "an additional rejecting condition must not erase the exact containment proof: {safe:#?}"
    );

    let unsafe_report = analyze(
        "store.erl",
        r#"-module(store).
-define(BASE, "/srv/assets").
-export([read/1]).
read(Req) ->
  Name = cowboy_req:path(Req),
  N = binary_to_list(Name),
  Path = filename:absname(filename:join(?BASE, N)),
  Root = filename:absname(?BASE) ++ "/",
  case not lists:prefix(Root, Path) andalso not lists:member("..", filename:split(N)) of
    true -> file:read_file(Path);
    false -> {error, eacces}
  end.
"#,
    );
    assert_eq!(
        sink_status(&unsafe_report, "erlang.path.file_read_file"),
        FindingStatus::Unsanitized,
        "opposite containment polarity must remain reportable"
    );
}

#[test]
fn erlang_finite_host_case_arm_credits_only_static_membership_and_no_redirect() {
    let source = |collection: &str, redirect: &str| {
        format!(
            r#"-module(fetch).
-export([get/1]).
-define(ALLOWED, ["api.example", "hooks.example"]).
get(Req) ->
  Url = cowboy_req:uri(Req),
  case uri_string:parse(Url) of
    #{{scheme := "https", host := Host}} ->
      case lists:member(Host, {collection}) of
        true -> httpc:request(get, {{Url, []}}, [{{autoredirect, {redirect}}}], []);
        false -> denied
      end;
    _ -> denied
  end.
"#
        )
    };
    let safe = analyze("fetch.erl", &source("?ALLOWED", "false"));
    assert_eq!(
        sink_status(&safe, "erlang.ssrf.httpc_request_tuple"),
        FindingStatus::Sanitized,
        "{safe:#?}"
    );

    for unsafe_source in [source("Allowed", "false"), source("?ALLOWED", "true")] {
        let report = analyze("fetch.erl", &unsafe_source);
        assert_eq!(
            sink_status(&report, "erlang.ssrf.httpc_request_tuple"),
            FindingStatus::Unsanitized,
            "dynamic membership or enabled redirects must fail closed: {report:#?}"
        );
    }
}
