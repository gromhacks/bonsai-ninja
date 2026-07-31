use super::*;

fn cost_bytes_ascii(s: &&str) -> u64 {
    s.len() as u64
}

#[test]
fn parse_context_accepts_k_and_m_shorthand() {
    assert_eq!(parse_context("32k").unwrap(), Some(32 * 1024));
    assert_eq!(parse_context("128K").unwrap(), Some(128 * 1024));
    assert_eq!(parse_context("1m").unwrap(), Some(1024 * 1024));
    assert_eq!(parse_context("4096").unwrap(), Some(4096));
}

#[test]
fn parse_context_accepts_uncapped_aliases() {
    assert_eq!(parse_context("0").unwrap(), None);
    assert_eq!(parse_context("all").unwrap(), None);
    assert_eq!(parse_context("uncapped").unwrap(), None);
    assert_eq!(parse_context("NONE").unwrap(), None);
    assert_eq!(parse_context("").unwrap(), None);
}

#[test]
fn parse_context_rejects_garbage() {
    assert!(parse_context("garbage").is_err());
    assert!(parse_context("12x").is_err());
    assert!(parse_context("k").is_err());
}

#[test]
fn page_arg_parses_first_number_and_cursor() {
    assert_eq!(PageArg::parse("").unwrap(), PageArg::First);
    assert_eq!(PageArg::parse("1").unwrap(), PageArg::First);
    assert_eq!(PageArg::parse("first").unwrap(), PageArg::First);
    assert_eq!(PageArg::parse("3").unwrap(), PageArg::Number(3));
    assert_eq!(PageArg::parse("next").unwrap(), PageArg::Next);
    assert_eq!(
        PageArg::parse("P:deadbeef").unwrap(),
        PageArg::Cursor("P:deadbeef".to_string())
    );
}

#[test]
fn page_arg_rejects_malformed_cursor() {
    assert!(PageArg::parse("P:short").is_err());
    assert!(PageArg::parse("P:DEADBEEF").is_err()); // uppercase disallowed
    assert!(PageArg::parse("P:GHIJKLMN").is_err()); // non-hex
    assert!(PageArg::parse("garbage").is_err());
    assert!(PageArg::parse("0").is_err());
}

#[test]
fn cursor_id_is_stable_and_eight_hex() {
    let a = cursor_id("calls", 0x1234_5678_9abc_def0, 0);
    let b = cursor_id("calls", 0x1234_5678_9abc_def0, 0);
    assert_eq!(a, b);
    assert!(a.starts_with("P:"));
    assert_eq!(a.len(), 10);
    assert!(a[2..]
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn cursor_id_differs_on_any_input_change() {
    let base = cursor_id("calls", 0xabcd, 0);
    assert_ne!(base, cursor_id("defs", 0xabcd, 0)); // command differs
    assert_ne!(base, cursor_id("calls", 0xabce, 0)); // filters differ
    assert_ne!(base, cursor_id("calls", 0xabcd, 1)); // offset differs
}

#[test]
fn bytes_to_tokens_matches_footer_heuristic() {
    assert_eq!(bytes_to_tokens(0), 0);
    assert_eq!(bytes_to_tokens(1), 1);
    assert_eq!(bytes_to_tokens(4), 1);
    assert_eq!(bytes_to_tokens(5), 2);
    assert_eq!(bytes_to_tokens(1024), 256);
}

#[test]
fn paginate_all_returns_everything() {
    let rows: Vec<&str> = vec!["a", "b", "c"];
    let cfg = PagingConfig::new(None, PageArg::First, None, true, FormatClass::Text);
    let (slice, info) = paginate(&rows, &cfg, "t", 0, cost_bytes_ascii).unwrap();
    assert_eq!(slice, rows);
    assert!(info.is_last);
    assert_eq!(info.total_pages, 1);
    assert_eq!(info.shown_rows, 3);
}

#[test]
fn paginate_fits_rows_under_budget() {
    // Each row is ~1 byte → 1 token. Budget 8 tokens after
    // 5% reserve (~7 usable) should fit ~7 rows per page.
    let rows: Vec<&str> = (0..20).map(|_| "x").collect();
    let cfg = PagingConfig::new(
        Some(8), // 8 tokens
        PageArg::First,
        None,
        false,
        FormatClass::Text,
    );
    let (slice, info) = paginate(&rows, &cfg, "t", 0, cost_bytes_ascii).unwrap();
    assert!(slice.len() <= 8, "slice len {} exceeds budget", slice.len());
    assert!(!slice.is_empty());
    assert!(!info.is_last);
    assert!(info.next_cursor.is_some());
}

#[test]
fn paginate_walks_pages_losslessly() {
    let rows: Vec<String> = (0..100).map(|i| format!("r{i:02}")).collect();
    let per_row_bytes = |r: &String| r.len() as u64;
    let budget_bytes = 32; // ~8 tokens/page
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = PageArg::First;
    let mut page_count = 0;
    loop {
        page_count += 1;
        let cfg = PagingConfig::new(Some(budget_bytes), cursor.clone(), None, false, FormatClass::Text);
        let (slice, info) = paginate(&rows, &cfg, "t", 0, per_row_bytes).unwrap();
        seen.extend(slice);
        assert!(page_count <= 200, "infinite loop");
        if let Some(nc) = info.next_cursor {
            cursor = PageArg::Cursor(nc);
        } else {
            break;
        }
    }
    assert_eq!(seen, rows, "pages must reconstitute the full row set");
}

#[test]
fn paginate_page_number_and_cursor_resolve_to_same_slice() {
    let rows: Vec<String> = (0..30).map(|i| format!("row-{i}")).collect();
    let per_row_bytes = |r: &String| r.len() as u64;
    let cfg_num = PagingConfig::new(Some(40), PageArg::Number(3), None, false, FormatClass::Text);
    let (slice_num, info_num) = paginate(&rows, &cfg_num, "t", 7, per_row_bytes).unwrap();
    let cfg_cursor = PagingConfig::new(
        Some(40),
        PageArg::Cursor(info_num.cursor.clone()),
        None,
        false,
        FormatClass::Text,
    );
    let (slice_cursor, info_cursor) = paginate(&rows, &cfg_cursor, "t", 7, per_row_bytes).unwrap();
    assert_eq!(slice_num, slice_cursor);
    assert_eq!(info_num.page_number, info_cursor.page_number);
    assert_eq!(info_num.cursor, info_cursor.cursor);
}

#[test]
fn paginate_rejects_a_well_formed_cursor_from_another_result_set() {
    let rows: Vec<String> = (0..30).map(|i| format!("row-{i}")).collect();
    let cfg = PagingConfig::new(
        Some(40),
        PageArg::Cursor("P:deadbeef".to_string()),
        None,
        false,
        FormatClass::Text,
    );

    let error = paginate(&rows, &cfg, "calls", 7, |row| row.len() as u64)
        .expect_err("an unknown opaque cursor must not silently replay page one");

    assert!(error
        .to_string()
        .contains("does not belong to this command result"));
}

#[test]
fn page_next_uses_last_rendered_cursor() {
    clear_cursor_history_for_tests();
    let rows: Vec<String> = (0..30).map(|i| format!("row-{i}")).collect();
    let per_row_bytes = |r: &String| r.len() as u64;
    let first_cfg = PagingConfig::new(Some(40), PageArg::First, None, false, FormatClass::Text);
    let (_first, first_info) = paginate(&rows, &first_cfg, "t-next", 11, per_row_bytes).unwrap();
    assert_eq!(first_info.page_number, 1);

    let next_cfg = PagingConfig::new(Some(40), PageArg::Next, None, false, FormatClass::Text);
    let (next_slice, next_info) = paginate(&rows, &next_cfg, "t-next", 11, per_row_bytes).unwrap();
    let cursor_cfg = PagingConfig::new(
        Some(40),
        PageArg::Cursor(first_info.next_cursor.expect("next cursor")),
        None,
        false,
        FormatClass::Text,
    );
    let (cursor_slice, cursor_info) = paginate(&rows, &cursor_cfg, "t-next", 11, per_row_bytes).unwrap();

    assert_eq!(next_info.page_number, 2);
    assert_eq!(next_slice, cursor_slice);
    assert_eq!(next_info.cursor, cursor_info.cursor);
    clear_cursor_history_for_tests();
}

#[test]
fn cursor_file_is_scoped_beneath_user_state() {
    let state = Path::new("/user-state");
    let path = cursor_file_in_state_dir(state);

    assert_eq!(path, state.join("bonsai-ninja/last-cursor.v2.json"));
    assert!(path.starts_with(state));
}

#[test]
fn cursor_store_key_does_not_disclose_paths_or_arguments() {
    let key = cursor_key_for_parts(
        "/private/work/customer",
        "security\0.\0--source\0secret-rule",
        "security/taint-analysis",
        0x1234,
    );

    assert_eq!(key.len(), 16);
    assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(!key.contains("customer"));
    assert!(!key.contains("secret-rule"));
}

#[test]
fn cursor_file_decoder_rejects_oversized_or_invalid_state() {
    assert!(decode_cursor_file(&vec![b' '; MAX_CURSOR_FILE_BYTES as usize + 1]).is_empty());

    let invalid = br#"{
        "0123456789abcdef": "not-a-cursor",
        "raw workspace path": "P:12345678",
        "fedcba9876543210": "P:deadbeef"
    }"#;
    let decoded = decode_cursor_file(invalid);
    assert_eq!(decoded.len(), 1);
    assert_eq!(
        decoded.get("fedcba9876543210").map(String::as_str),
        Some("P:deadbeef")
    );

    let too_many: BTreeMap<String, String> = (0..=MAX_CURSOR_HISTORY_ENTRIES)
        .map(|index| (format!("{index:016x}"), "P:deadbeef".to_string()))
        .collect();
    let bytes = serde_json::to_vec(&too_many).expect("encode cursor state");
    assert!(bytes.len() as u64 <= MAX_CURSOR_FILE_BYTES);
    assert!(decode_cursor_file(&bytes).is_empty());
}

#[test]
fn cursor_history_rejects_malformed_cached_cursor() {
    clear_cursor_history_for_tests();
    write_last_cursor("untrusted-cache", 19, "not-a-cursor");
    assert_eq!(last_cursor("untrusted-cache", 19), None);
}

#[test]
fn paginate_page_size_overrides_context() {
    let rows: Vec<&str> = vec!["a"; 30];
    let cfg = PagingConfig::new(
        Some(10_000), // generous
        PageArg::First,
        Some(5), // but cap to 5 per page
        false,
        FormatClass::Text,
    );
    let (slice, info) = paginate(&rows, &cfg, "t", 0, cost_bytes_ascii).unwrap();
    assert_eq!(slice.len(), 5);
    assert_eq!(info.total_pages, 6);
}

#[test]
fn paginate_handles_empty_input() {
    let rows: Vec<&str> = Vec::new();
    let cfg = PagingConfig::new(Some(1024), PageArg::First, None, false, FormatClass::Text);
    let (slice, info) = paginate(&rows, &cfg, "t", 0, cost_bytes_ascii).unwrap();
    assert!(slice.is_empty());
    assert!(info.is_last);
    assert_eq!(info.total_rows, 0);
}

#[test]
fn paginate_fits_single_oversized_row() {
    // One row that exceeds the entire budget. Paging must
    // still render it (on its own page) so the user sees
    // *something* — the alternative is silent drop, which
    // breaks the loss-free guarantee.
    let rows: Vec<&str> = vec!["huge_row_bigger_than_budget"];
    let cfg = PagingConfig::new(Some(4), PageArg::First, None, false, FormatClass::Text);
    let (slice, info) = paginate(&rows, &cfg, "t", 0, cost_bytes_ascii).unwrap();
    assert_eq!(slice.len(), 1);
    assert!(info.tokens_used > info.budget.unwrap_or(0));
}

#[test]
fn effective_budget_respects_format_class() {
    let cfg_text = PagingConfig::new(None, PageArg::First, None, false, FormatClass::Text);
    assert_eq!(cfg_text.effective_budget(), Some(DEFAULT_CONTEXT_TEXT));
    let cfg_json = PagingConfig::new(None, PageArg::First, None, false, FormatClass::Programmatic);
    assert_eq!(cfg_json.effective_budget(), Some(DEFAULT_CONTEXT_TEXT));
    let cfg_dot = PagingConfig::new(None, PageArg::First, None, false, FormatClass::RenderOnly);
    assert_eq!(cfg_dot.effective_budget(), None);
    let cfg_json_all = PagingConfig::new(None, PageArg::First, None, true, FormatClass::Programmatic);
    assert_eq!(cfg_json_all.effective_budget(), None);
}

#[test]
fn json_wrapped_by_default_unless_explicitly_uncapped() {
    // Default programmatic output is token-budgeted, so it includes
    // page metadata and a rows array.
    let cfg = PagingConfig::new(None, PageArg::First, None, false, FormatClass::Programmatic);
    assert!(cfg.json_wrapped());
    // Explicit --context → wrap.
    let cfg_ctx = PagingConfig::new(Some(1024), PageArg::First, None, false, FormatClass::Programmatic);
    assert!(cfg_ctx.json_wrapped());
    // Explicit --page → wrap.
    let cfg_page = PagingConfig::new(None, PageArg::Number(2), None, false, FormatClass::Programmatic);
    assert!(cfg_page.json_wrapped());
    // Explicit uncapped output keeps the historical bare array shape.
    let cfg_all = PagingConfig::new(None, PageArg::First, None, true, FormatClass::Programmatic);
    assert!(!cfg_all.json_wrapped());
    // Text mode never JSON-wraps.
    let cfg_text = PagingConfig::new(Some(1024), PageArg::Number(2), None, false, FormatClass::Text);
    assert!(!cfg_text.json_wrapped());
}

#[test]
fn hash_filters_is_stable_and_order_sensitive() {
    let a = hash_filters(&[("kind", "function"), ("file", "gateway.py")]);
    let b = hash_filters(&[("kind", "function"), ("file", "gateway.py")]);
    assert_eq!(a, b);
    let c = hash_filters(&[("file", "gateway.py"), ("kind", "function")]);
    assert_ne!(a, c, "filter order matters for the hash");
}
