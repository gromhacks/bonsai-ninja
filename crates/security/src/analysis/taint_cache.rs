use crate::loader::Rulepack;
use crate::rule::RuleKind;
use bonsai_common::Precision;
use bonsai_workspace::Workspace;
use std::path::PathBuf;

pub(super) fn config_fingerprint(
    pack: &Rulepack,
    mode: &'static str,
    max_precision: Option<Precision>,
) -> u64 {
    let rule_content_fingerprint = *pack.taint_graph_rule_content_fingerprint.get_or_init(|| {
        let mut rule_tokens = Vec::new();
        let mut rules = pack.all_rules();
        rules.sort_by(|a, b| {
            a.language
                .cmp(&b.language)
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.id.cmp(&b.id))
        });
        for rule in rules.into_iter().filter(|rule| rule.enabled) {
            rule_tokens.push(format!(
                "rule:{}:{}:{}",
                rule.language,
                rule_kind_token(rule.kind),
                rule.id
            ));
            rule_tokens
                .push(serde_json::to_string(rule).unwrap_or_else(|_| format!("rule-json-error:{}", rule.id)));
        }
        bonsai_hash::fnv1a_names64(&rule_tokens)
    });
    let tokens = vec![
        "taint-graph-config-v2".to_string(),
        format!("mode={mode}"),
        format!(
            "max_precision={}",
            max_precision.map(precision_label).unwrap_or("all")
        ),
        format!("rule_content={rule_content_fingerprint}"),
    ];
    bonsai_hash::fnv1a_names64(&tokens)
}

#[derive(Clone, Debug)]
pub(super) struct WorkspaceCachePrepareReport {
    pub sidecar_path: Option<PathBuf>,
    pub disk_skipped_reason: Option<&'static str>,
    pub config_changed: bool,
    pub resident_entries_before: usize,
    pub total_entries_before: usize,
    pub resident_capacity: usize,
    pub temp_files_removed: usize,
    pub disk_entries_loaded: usize,
    pub persistence_enabled: bool,
    pub persist_started: bool,
    pub load_error: Option<String>,
    pub persist_error: Option<String>,
}

impl WorkspaceCachePrepareReport {
    #[must_use]
    pub(super) fn detail(&self) -> String {
        let sidecar = self
            .sidecar_path
            .as_ref()
            .map_or_else(|| "none".to_string(), |path| path.display().to_string());
        let state = if let Some(reason) = self.disk_skipped_reason {
            format!("disk skipped; reason={reason}")
        } else if self.disk_entries_loaded > 0 {
            if self.config_changed {
                "disk hit; resident config refreshed".to_string()
            } else {
                "disk hit".to_string()
            }
        } else if self.config_changed {
            "miss; resident config refreshed".to_string()
        } else if self.total_entries_before > 0 {
            "memory hit".to_string()
        } else {
            "miss".to_string()
        };
        let persist = if self.persistence_enabled {
            if self.persist_started {
                "write-through on"
            } else {
                "write-through requested but not started"
            }
        } else {
            "write-through off"
        };
        let mut detail = format!(
            "{state}; sidecar={sidecar}; disk_entries={}; resident_before={}/{}; total_before={}; temp_removed={}; {persist}",
            self.disk_entries_loaded,
            self.resident_entries_before,
            self.resident_capacity,
            self.total_entries_before,
            self.temp_files_removed
        );
        if let Some(error) = &self.load_error {
            detail.push_str(&format!("; load_error={error}"));
        }
        if let Some(error) = &self.persist_error {
            detail.push_str(&format!("; persist_error={error}"));
        }
        detail
    }
}

pub(super) fn prepare_workspace_cache(
    ws: &Workspace,
    namespace: &'static str,
    config_fingerprint: u64,
) -> WorkspaceCachePrepareReport {
    let index = ws.taint_index();
    let resident_entries_before = index.resident_len();
    let total_entries_before = index.len();
    let resident_capacity = index.resident_capacity();
    let config_changed = index.clear_for_config(config_fingerprint);
    let Some(root) = ws.db().workspace_root() else {
        return WorkspaceCachePrepareReport {
            sidecar_path: None,
            disk_skipped_reason: Some("no workspace root"),
            config_changed,
            resident_entries_before,
            total_entries_before,
            resident_capacity,
            temp_files_removed: 0,
            disk_entries_loaded: 0,
            persistence_enabled: false,
            persist_started: false,
            load_error: None,
            persist_error: None,
        };
    };
    if !ws.is_complete_workspace_index() {
        return WorkspaceCachePrepareReport {
            sidecar_path: None,
            disk_skipped_reason: Some("scoped workspace"),
            config_changed,
            resident_entries_before,
            total_entries_before,
            resident_capacity,
            temp_files_removed: 0,
            disk_entries_loaded: 0,
            persistence_enabled: false,
            persist_started: false,
            load_error: None,
            persist_error: None,
        };
    }
    let sidecar = bonsai_workspace::taint_index::TaintGraphIndex::sidecar_path_for_config_namespace(
        &root,
        namespace,
        config_fingerprint,
    );
    let mut temp_files_removed = 0usize;
    let mut disk_entries_loaded = 0usize;
    let mut load_error = None;
    let mut persist_started = false;
    let mut persist_error = None;
    match bonsai_workspace::taint_index::cleanup_sidecar_temp_files(&sidecar) {
        Ok(removed) => temp_files_removed = removed,
        Err(err) => {
            tracing::warn!(
                path = %sidecar.display(),
                error = %err,
                "taint graph factstore temp cleanup failed"
            );
            load_error = Some(format!("temp cleanup failed: {err}"));
        }
    }
    match index.load_from_disk_for_config(&sidecar, ws.db(), config_fingerprint) {
        Ok(entries) => disk_entries_loaded = entries,
        Err(err) => {
            tracing::warn!(
                path = %sidecar.display(),
                error = %err,
                "taint graph factstore load failed"
            );
            load_error = Some(err.to_string());
        }
    }
    let persistence_enabled = persistence_enabled();
    if persistence_enabled {
        match index.begin_persist_to_disk(&sidecar, ws.db(), config_fingerprint) {
            Ok(started) => persist_started = started,
            Err(err) => {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %err,
                    "taint graph factstore write-through setup failed"
                );
                persist_error = Some(err.to_string());
            }
        }
    }
    WorkspaceCachePrepareReport {
        sidecar_path: Some(sidecar),
        disk_skipped_reason: None,
        config_changed,
        resident_entries_before,
        total_entries_before,
        resident_capacity,
        temp_files_removed,
        disk_entries_loaded,
        persistence_enabled,
        persist_started,
        load_error,
        persist_error,
    }
}

pub(super) fn finish_workspace_cache(ws: &Workspace) -> Option<usize> {
    match ws.taint_index().finish_persist_to_disk(ws.db()) {
        Ok(written) => Some(written),
        Err(err) => {
            tracing::warn!(error = %err, "taint graph factstore finish failed");
            None
        }
    }
}

fn persistence_enabled() -> bool {
    std::env::var("BONSAI_TAINT_GRAPH_PERSIST")
        .ok()
        .is_none_or(|value| !matches!(value.as_str(), "0" | "false" | "no" | "off"))
}

fn precision_label(precision: Precision) -> &'static str {
    match precision {
        Precision::Exact => "exact",
        Precision::Narrowed => "narrowed",
        Precision::OverApproximate => "over-approximate",
        Precision::Unknown => "unknown",
    }
}

fn rule_kind_token(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Source => "source",
        RuleKind::Sink => "sink",
        RuleKind::Sanitizer => "sanitizer",
        RuleKind::Typing => "typing",
    }
}
