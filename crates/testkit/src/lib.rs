//! Shared test harness.

use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::Workspace;
use std::sync::Arc;

/// Build a workspace with just the given adapters registered, ingesting a
/// table of (path, text) pairs into the VFS.
pub fn workspace_with(adapters: Vec<AdapterArc>, files: &[(&str, &str)]) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    for adapter in adapters {
        registry.register(adapter);
    }
    let ws = Workspace::new(registry);
    for (path, text) in files {
        ws.vfs().write((*path).to_string(), Arc::<str>::from(*text));
    }
    ws
}
