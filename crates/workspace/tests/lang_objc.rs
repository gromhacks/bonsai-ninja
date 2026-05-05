//! Per-construct tests for the Objective-C adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_objc::ObjCAdapter::new()), "/w/a.m", src)
}

#[test]
fn selector_pieces_are_parameter_annotations() {
    let w = make(
        "@interface App : NSObject\n\
         - (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options;\n\
         @end\n\
         @implementation App\n\
         - (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options {\n\
           return YES;\n\
         }\n\
         @end\n",
    );
    let annotations = param_annotations_of(&w, "application");
    assert!(
        annotations.iter().any(|a| a.contains(&"openURL".to_string())),
        "{annotations:?}"
    );
    assert!(
        annotations.iter().any(|a| a.contains(&"options".to_string())),
        "{annotations:?}"
    );
}
