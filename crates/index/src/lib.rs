//! Cross-file declaration and reference index.
//!
//! Adapters produce a per-file [`DeclIndex`] with
//! symbols that are *locally* unique inside that file. The global index
//! remaps those to workspace-unique `SymbolId`s so downstream code has one
//! flat namespace. The local `(FileId, local_symbol)` pair is still
//! retrievable when an adapter needs to go back to the per-file data.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{short_qualified_tail, FileId, SymbolId};
use bonsai_lang_api::{Decl, DeclIndex, DeclKind, FlowEvent, Ref};
use serde::{Deserialize, Serialize};

/// A merged view over all per-file decl indices.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GlobalIndex {
    /// All per-file indices, indexed by the file they belong to.
    by_file: AHashMap<FileId, DeclIndex>,
    /// Global symbol table. Index = global raw id.
    /// Each entry: `Some((declaring_file, local_decl_index_in_that_file))`
    /// for live decls, `None` for slots whose file was removed
    /// (tombstoned). Compaction would invalidate live `SymbolId`s,
    /// so we keep the indices stable and clear the payload instead.
    entries: Vec<Option<(FileId, usize)>>,
    /// Lookup by qualified name -> list of global symbols.
    by_name: AHashMap<String, Vec<SymbolId>>,
    /// Reverse ref view: global symbol -> list of (file, ref index in that file's index).
    refs_by_symbol: AHashMap<SymbolId, Vec<(FileId, usize)>>,
    /// Per-file slot positions in `entries`. Lets `remove_file`
    /// tombstone in O(slots-in-file) instead of scanning the whole
    /// table on every removal — important for long-running
    /// indexers with frequent file edits.
    ///
    /// `serde(skip)` because a deserialised GlobalIndex with a
    /// `default()` empty map but populated `entries`/`by_file`
    /// would silently no-op subsequent `remove_file` tombstones.
    /// `GlobalIndex` isn't currently persisted; if that changes,
    /// add a `Deserialize` adaptor that rebuilds the reverse map
    /// from `entries`.
    #[serde(skip)]
    slots_by_file: AHashMap<FileId, Vec<usize>>,
}

impl GlobalIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a per-file index. Local symbol ids in `index` are remapped to
    /// workspace-unique global ids; `by_file` stores the *remapped* index so
    /// lookups by file return global ids.
    pub fn insert(&mut self, mut index: DeclIndex) {
        bonsai_lang_api::apply_call_receiver_types(&mut index);
        bonsai_lang_api::apply_assign_value_kind(&mut index);
        bonsai_lang_api::apply_assign_call_result_types(&mut index);
        let file = index.file;
        if self.by_file.contains_key(&file) {
            self.remove_file(file);
        }
        // Build a local->global remap.
        let mut local_to_global: AHashMap<SymbolId, SymbolId> = AHashMap::new();
        let slot_positions = self.slots_by_file.entry(file).or_default();
        for (local_idx, decl) in index.defs.iter().enumerate() {
            // INTENTIONAL: panic at the structural u32 boundary.
            // `SymbolId` is a `u32` newtype that flows through every
            // graph artifact (callgraph edges, dataflow sidecar,
            // export JSON). A workspace with 2^32 declarations would
            // require redesigning the ID type, not a runtime
            // fallback. The panic surfaces that capacity limit
            // cleanly instead of silently wrapping into the wrong
            // decl.
            let global_raw = u32::try_from(self.entries.len()).expect("symbol overflow");
            let global_sym = SymbolId::new(global_raw);
            local_to_global.insert(decl.symbol, global_sym);
            slot_positions.push(self.entries.len());
            self.entries.push(Some((file, local_idx)));
        }
        // Rewrite the index in place to use global ids.
        for decl in &mut index.defs {
            decl.symbol = *local_to_global.get(&decl.symbol).expect("decl not remapped");
            if let Some(parent) = decl.parent {
                decl.parent = local_to_global.get(&parent).copied();
            }
            // Index by BOTH bare `name` and `qualified_name` (when
            // present and distinct). Bare-name lookup remains the
            // legacy path for callers that don't yet build a
            // ResolveContext; the qualified-name lookup lets the
            // semantic-identity resolver narrow precisely. See
            // `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
            self.by_name
                .entry(decl.name.clone())
                .or_default()
                .push(decl.symbol);
            if let Some(qname) = &decl.qualified_name {
                if qname != &decl.name {
                    self.by_name.entry(qname.clone()).or_default().push(decl.symbol);
                }
            }
        }
        for reference in &mut index.refs {
            if let Some(resolved) = reference.resolved {
                reference.resolved = local_to_global.get(&resolved).copied();
            }
        }
        for (idx, reference) in index.refs.iter().enumerate() {
            if let Some(target) = reference.resolved {
                self.refs_by_symbol.entry(target).or_default().push((file, idx));
            }
        }
        self.by_file.insert(file, index);
    }

    /// Finish workspace-wide semantic facts that need all files.
    ///
    /// Per-file adapter facts already populate direct receiver types
    /// (`Child c; c.sink()`). This pass extends those facts through
    /// indexed base-class declarations across the whole workspace so
    /// downstream consumers can match `[Base, sink]` on a `Child`
    /// receiver without falling back to receiver-name heuristics.
    pub fn finalize_semantic_facts(&mut self) {
        let bases_by_type = self.bases_by_type_name();
        for index in self.by_file.values_mut() {
            for decl in &mut index.defs {
                enrich_receiver_types_in_events(&mut decl.flow_events, &bases_by_type);
            }
        }
    }

    /// Drop every cached fact derived from `file`: per-file indexes,
    /// name-table entries, ref backlinks, and tombstone the global
    /// id slots so old SymbolIds resolve to `None`.
    pub fn remove_file(&mut self, file: FileId) {
        if let Some(prev) = self.by_file.remove(&file) {
            for decl in &prev.defs {
                if let Some(symbols) = self.by_name.get_mut(&decl.name) {
                    symbols.retain(|sym| *sym != decl.symbol);
                }
                if let Some(qname) = &decl.qualified_name {
                    if qname != &decl.name {
                        if let Some(symbols) = self.by_name.get_mut(qname) {
                            symbols.retain(|sym| *sym != decl.symbol);
                        }
                    }
                }
            }
            for list in self.refs_by_symbol.values_mut() {
                list.retain(|(f, _)| *f != file);
            }
            // Tombstone the global slot table so a lingering SymbolId
            // from the removed file resolves to `None` rather than
            // pointing at whatever decl now sits at the same
            // `local_idx` after a re-insert.
            if let Some(slots) = self.slots_by_file.remove(&file) {
                for idx in slots {
                    if let Some(slot) = self.entries.get_mut(idx) {
                        *slot = None;
                    }
                }
            }
        }
    }

    fn bases_by_type_name(&self) -> AHashMap<String, Vec<String>> {
        let mut candidates: AHashMap<String, Option<Vec<String>>> = AHashMap::new();
        for decl in self.by_file.values().flat_map(|index| index.defs.iter()) {
            if !matches!(
                decl.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
            ) || decl.bases.is_empty()
            {
                continue;
            }
            let mut bases = decl.bases.clone();
            dedup_strings(&mut bases);
            for key in type_name_keys(decl.name.as_str(), decl.qualified_name.as_deref()) {
                candidates
                    .entry(key)
                    .and_modify(|existing| {
                        if existing.as_ref().is_some_and(|known| known == &bases) {
                            return;
                        }
                        // Same type spelling resolved to different
                        // class declarations. Fail closed for this
                        // key instead of merging unrelated ancestry.
                        *existing = None;
                    })
                    .or_insert_with(|| Some(bases.clone()));
            }
        }
        candidates
            .into_iter()
            .filter_map(|(key, bases)| bases.map(|bases| (key, bases)))
            .collect()
    }

    /// Per-file decl index, keyed on global ids. Returns `None` when
    /// the file has not been ingested.
    pub fn file_index(&self, file: FileId) -> Option<&DeclIndex> {
        self.by_file.get(&file)
    }

    /// Every workspace symbol whose `name` or `qualified_name` matches
    /// the lookup string. Empty when nothing matches.
    pub fn find_by_name(&self, qualified: &str) -> &[SymbolId] {
        self.by_name.get(qualified).map_or(&[][..], Vec::as_slice)
    }

    /// File where `symbol` was declared, or `None` for tombstoned
    /// (file-removed) entries.
    pub fn declaring_file(&self, symbol: SymbolId) -> Option<FileId> {
        self.entries
            .get(symbol.raw() as usize)
            .and_then(|slot| slot.map(|(file, _)| file))
    }

    /// Look up `symbol`'s declaration. `None` for unknown or
    /// tombstoned ids.
    pub fn decl_of(&self, symbol: SymbolId) -> Option<&Decl> {
        let (file, local_idx) = (*self.entries.get(symbol.raw() as usize)?)?;
        self.by_file.get(&file).and_then(|idx| idx.defs.get(local_idx))
    }

    /// Every reference site that resolves to `symbol`, paired with
    /// the file it lives in.
    pub fn refs_to(&self, symbol: SymbolId) -> Vec<(FileId, &Ref)> {
        self.refs_by_symbol
            .get(&symbol)
            .map(|list| {
                list.iter()
                    .filter_map(|(file, idx)| {
                        self.by_file
                            .get(file)
                            .and_then(|decl_index| decl_index.refs.get(*idx).map(|r| (*file, r)))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Deterministic iteration: returns FileIds in ascending order so two
    /// runs over the same index produce identical output. Without this,
    /// callers iterate `by_file`'s AHashMap keys directly and their
    /// downstream ordering (hits, flow numbers) varies run-to-run.
    pub fn all_files(&self) -> impl Iterator<Item = FileId> + '_ {
        let mut ids: Vec<FileId> = self.by_file.keys().copied().collect();
        ids.sort();
        ids.into_iter()
    }

    /// Every decl that lives in `file`, in adapter-emitted order.
    pub fn decls_in(&self, file: FileId) -> &[Decl] {
        self.by_file
            .get(&file)
            .map_or(&[][..], |decl_index| decl_index.defs.as_slice())
    }

    /// Function-shaped decls (functions, methods, constructors) in
    /// `file`. Used by call-graph construction and the matcher's
    /// receiver-type filter.
    pub fn functions_in(&self, file: FileId) -> impl Iterator<Item = &Decl> {
        self.decls_in(file).iter().filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
    }

    /// Total live decls across every ingested file.
    pub fn len(&self) -> usize {
        self.by_file.values().map(|index| index.defs.len()).sum()
    }

    /// True when every per-file index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_file.values().all(|index| index.defs.is_empty())
    }
}

fn enrich_receiver_types_in_events(events: &mut [FlowEvent], bases_by_type: &AHashMap<String, Vec<String>>) {
    for event in events {
        match event {
            FlowEvent::Call { receiver_types, .. } => {
                let originals = receiver_types.clone();
                for ty in originals {
                    push_type_and_bases(receiver_types, &ty, bases_by_type, &mut AHashSet::new());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_receiver_types_in_events(then_events, bases_by_type);
                enrich_receiver_types_in_events(else_events, bases_by_type);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_receiver_types_in_events(body, bases_by_type);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_receiver_types_in_events(body, bases_by_type);
                enrich_receiver_types_in_events(catch_events, bases_by_type);
                enrich_receiver_types_in_events(finally_events, bases_by_type);
            }
            FlowEvent::Assign { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

fn push_type_and_bases(
    receiver_types: &mut Vec<String>,
    ty: &str,
    bases_by_type: &AHashMap<String, Vec<String>>,
    seen: &mut AHashSet<String>,
) {
    let key = type_name_key(ty);
    if key.is_empty() || !seen.insert(key.clone()) {
        return;
    }
    push_unique(receiver_types, key.clone());
    if let Some(bases) = bases_by_type.get(&key) {
        for base in bases {
            push_type_and_bases(receiver_types, base, bases_by_type, seen);
        }
    }
}

fn type_name_keys(name: &str, qualified_name: Option<&str>) -> Vec<String> {
    let mut out = vec![type_name_key(name)];
    if let Some(qname) = qualified_name {
        out.push(type_name_key(qname));
    }
    dedup_strings(&mut out);
    out.retain(|key| !key.is_empty());
    out
}

fn type_name_key(name: &str) -> String {
    let normalized = name
        .trim()
        .trim_start_matches(['&', '*', '$', '@', '%'])
        .trim_end_matches("()")
        .replace('\\', "::");
    short_qualified_tail(&normalized)
        .split('<')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = AHashSet::new();
    values.retain(|value| !value.is_empty() && seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::{FileId, Span, SymbolId};
    use bonsai_lang_api::Visibility;

    fn decl(file: FileId, local_symbol: u32, name: &str) -> Decl {
        let span = Span::new(file, 0, u64::try_from(name.len()).unwrap());
        Decl {
            symbol: SymbolId::new(local_symbol),
            kind: DeclKind::Function,
            name: name.to_string(),
            qualified_name: Some(format!("file{}::{name}", file.raw())),
            module_path: bonsai_lang_api::ModulePath::default(),
            span,
            name_span: span,
            visibility: Visibility::Private,
            parent: None,
            body_span: Some(span),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
        }
    }

    #[test]
    fn len_and_empty_track_live_decls_after_removal() {
        let file = FileId::new(7);
        let mut index = GlobalIndex::new();
        index.insert(DeclIndex {
            file,
            defs: vec![decl(file, 0, "one"), decl(file, 1, "two")],
            refs: Vec::new(),
            strings: Vec::new(),
            comments: Vec::new(),
        });

        assert_eq!(index.len(), 2);
        assert!(!index.is_empty());

        index.remove_file(file);

        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
        assert!(index.find_by_name("file7::one").is_empty());
    }

    #[test]
    fn reinserting_file_replaces_name_lookup_entries() {
        let file = FileId::new(3);
        let mut index = GlobalIndex::new();
        index.insert(DeclIndex {
            file,
            defs: vec![decl(file, 0, "old")],
            refs: Vec::new(),
            strings: Vec::new(),
            comments: Vec::new(),
        });
        index.insert(DeclIndex {
            file,
            defs: vec![decl(file, 0, "new")],
            refs: Vec::new(),
            strings: Vec::new(),
            comments: Vec::new(),
        });

        assert_eq!(index.len(), 1);
        assert!(index.find_by_name("file3::old").is_empty());
        let new_symbols = index.find_by_name("file3::new");
        assert_eq!(new_symbols.len(), 1);
        assert_eq!(
            index.decl_of(new_symbols[0]).map(|d| d.name.as_str()),
            Some("new")
        );
    }
}
