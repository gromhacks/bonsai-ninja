use std::path::{Path, PathBuf};

use bonsai_security::{FindingStatus, TaintAnalysisOptions};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

#[test]
fn finite_dictionary_collection_helper_cleans_only_the_mapped_sql_identifier_path() {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "Sources/OrderHandler.m",
        r#"
#import <Foundation/Foundation.h>
#import "OrderRepo.h"

@implementation OrderHandler
- (void)handleOrders:(GCDWebServerRequest *)request {
    NSString *raw = request.query[@"sort"] ?: @"id";
    NSMutableArray<NSString *> *keys = [NSMutableArray array];
    [keys addObject:raw];
    [OrderRepo listSafe:keys];
    [OrderRepo listUnsafe:keys];
}
@end
"#,
    );
    ws.vfs().write(
        "Sources/OrderRepo.m",
        r#"
#import <Foundation/Foundation.h>
#import <sqlite3.h>
extern sqlite3 *gDB;

@implementation OrderRepo
+ (NSArray<NSString *> *)finiteKeys:(NSArray<NSString *> *)keys {
    NSDictionary *allowed = @{@"total": @"total", @"created_at": @"created_at", @"id": @"id"};
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *key in keys) {
        NSString *column = allowed[key];
        if (column) [out addObject:column];
    }
    if (out.count == 0) [out addObject:@"id"];
    return out;
}

+ (void)listSafe:(NSArray<NSString *> *)keys {
    NSString *columns = [[self finiteKeys:keys] componentsJoinedByString:@", "];
    NSString *sql = [NSString stringWithFormat:@"SELECT id FROM orders ORDER BY %@", columns];
    sqlite3_exec(gDB, [sql UTF8String], NULL, NULL, NULL);
}

+ (void)listUnsafe:(NSArray<NSString *> *)keys {
    NSString *columns = [keys componentsJoinedByString:@", "];
    NSString *sql = [NSString stringWithFormat:@"SELECT id FROM orders ORDER BY %@", columns];
    sqlite3_exec(gDB, [sql UTF8String], NULL, NULL, NULL);
}
@end
"#,
    );

    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let report = bonsai_security::run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("Objective-C finite collection analysis");

    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "objc.sqli.sqlite3_exec"
                && finding.finding.sink.enclosing_fn.as_deref() == Some("listUnsafe")
                && finding.finding.status == FindingStatus::Unsanitized
        }),
        "the direct join must remain an unsanitized SQL flow: {:#?}",
        report.findings
    );
    assert!(
        report.findings.iter().all(|finding| {
            finding.finding.sink.enclosing_fn.as_deref() != Some("listSafe")
                || finding.finding.status != FindingStatus::Unsanitized
        }),
        "a collection populated only from compiler-proven finite dictionary values must be clean: {:#?}",
        report.findings
    );
}
