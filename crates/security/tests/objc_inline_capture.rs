use bonsai_security::{FindingStatus, TaintAnalysisOptions};
use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

#[test]
fn inline_capture_and_finite_url_guard_require_exact_scheme_and_static_host_facts() {
    let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("temporary persisted workspace inside the writable checkout");
    let files = [
        (
            "Sources/Queue.m",
            r#"
#import <Foundation/Foundation.h>
@implementation Queue
+ (void)submit:(void (^)(void))work {
  dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), work);
}
@end
"#,
        ),
        (
            "Sources/Handler.m",
            r#"
#import <Foundation/Foundation.h>
@implementation Handler
- (void)handle:(GCDWebServerRequest *)request {
  NSString *url = request.query[@"url"] ?: @"";
  [Queue submit:^{
    [Client fetch:url];
    [Client safeFetch:url];
    [Client dynamicFetch:url allowedHost:url];
    [Client missingScheme:url];
  }];
}
@end
"#,
        ),
        (
            "Sources/Client.m",
            r#"
#import <Foundation/Foundation.h>
@implementation Client
+ (NSSet<NSString *> *)allowedHosts {
  static NSSet *hosts;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    hosts = [NSSet setWithObjects:@"api.example.test", @"webhooks.example.test", nil];
  });
  return hosts;
}
+ (void)fetch:(NSString *)urlString {
  NSURL *url = [NSURL URLWithString:urlString];
  [NSData dataWithContentsOfURL:url];
}
+ (void)safeFetch:(NSString *)urlString {
  NSURL *url = [NSURL URLWithString:urlString];
  if (![url.scheme isEqualToString:@"https"] || ![[self allowedHosts] containsObject:url.host]) {
    return;
  }
  [NSData dataWithContentsOfURL:url];
}
+ (void)dynamicFetch:(NSString *)urlString allowedHost:(NSString *)allowedHost {
  NSURL *url = [NSURL URLWithString:urlString];
  NSSet *hosts = [NSSet setWithObjects:allowedHost, nil];
  if (![url.scheme isEqualToString:@"https"] || ![hosts containsObject:url.host]) {
    return;
  }
  [NSData dataWithContentsOfURL:url];
}
+ (void)missingScheme:(NSString *)urlString {
  NSURL *url = [NSURL URLWithString:urlString];
  if (![[self allowedHosts] containsObject:url.host]) {
    return;
  }
  [NSData dataWithContentsOfURL:url];
}
+ (void)fixedPartner {
  NSURL *url = [NSURL URLWithString:@"https://api.example.test/status"];
  [NSData dataWithContentsOfURL:url];
}
@end
"#,
        ),
    ];
    for (relative, source) in files {
        let path = root.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture directory");
        std::fs::write(path, source).expect("write fixture source");
    }

    let workspace =
        bonsai_workspace::Workspace::index(root.path(), bonsai_adapters::all_languages_registry())
            .expect("index Objective-C workspace");
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let report = bonsai_security::run_taint_analysis(
        &workspace,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("run taint analysis");

    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "objc.source.gcdwebserver_request_param"
                && finding.finding.sink.rule_id == "objc.ssrf.nsdata_contents_of_url"
                && finding.finding.sink.enclosing_fn.as_deref() == Some("fetch")
                && finding.finding.status == FindingStatus::Unsanitized
                && finding
                    .finding
                    .chain_display
                    .iter()
                    .any(|function| function.starts_with("<lambda@"))
        }),
        "the exact typed query read must cross its inline lexical capture into the URL consumer: {:#?}",
        report.findings
    );
    for expected in ["dynamicFetch", "missingScheme"] {
        assert!(
            report.findings.iter().any(|finding| {
                finding.finding.sink.rule_id == "objc.ssrf.nsdata_contents_of_url"
                    && finding.finding.sink.enclosing_fn.as_deref() == Some(expected)
                    && finding.finding.status == FindingStatus::Unsanitized
            }),
            "a dynamic allowlist or missing scheme proof must remain unsafe ({expected}): {:#?}",
            report.findings
        );
    }
    assert!(
        report.findings.iter().all(|finding| !matches!(
            finding.finding.sink.enclosing_fn.as_deref(),
            Some("safeFetch" | "fixedPartner")
        )),
        "a complete finite guard and a literal URL must remain clean: {:#?}",
        report.findings
    );
}
