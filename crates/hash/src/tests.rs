use super::*;

#[test]
fn empty_input_returns_offset_basis() {
    assert_eq!(fnv1a_str_slice64(&[]), FNV_OFFSET_BASIS);
    assert_eq!(fnv1a_bytes64(&[]), FNV_OFFSET_BASIS);
    assert_eq!(fnv1a_names64(&[]), FNV_OFFSET_BASIS);
}

#[test]
fn null_separator_distinguishes_partitions() {
    let a = fnv1a_str_slice64(&["ab", "c"]);
    let b = fnv1a_str_slice64(&["a", "bc"]);
    assert_ne!(a, b, "null separator must distinguish list shapes");
}

#[test]
fn names_and_str_slice_match_for_same_input() {
    let names = vec!["alpha".to_string(), "beta".to_string()];
    let str_slice: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(fnv1a_names64(&names), fnv1a_str_slice64(&str_slice));
}

#[test]
fn bytes64_is_standard_fnv1a_64() {
    // Reference vector: FNV-1a-64 of "foobar" = 0x85944171f73967e8.
    // (RFC test vector.)
    assert_eq!(fnv1a_bytes64(b"foobar"), 0x8594_4171_f739_67e8);
}

#[test]
fn low32_is_truncation_of_64() {
    let names = vec!["x".to_string(), "y".to_string()];
    let full = fnv1a_names64(&names);
    assert_eq!(fnv1a_names_low32(&names), (full & 0xFFFF_FFFF) as u32);
    assert_eq!(fnv1a_low32(full), (full & 0xFFFF_FFFF) as u32);
}

#[test]
fn streaming_matches_one_shot() {
    let one_shot = fnv1a_bytes64(b"abc");
    let mut hasher = Hasher::new();
    hasher.absorb(b"a");
    hasher.absorb(b"b");
    hasher.absorb(b"c");
    assert_eq!(hasher.finish(), one_shot);
}

#[test]
fn streaming_with_separators_matches_str_slice() {
    let names = ["alpha", "beta", "gamma"];
    let mut hasher = Hasher::new();
    for name in &names {
        hasher.absorb(name.as_bytes());
        hasher.absorb_separator();
    }
    assert_eq!(hasher.finish(), fnv1a_str_slice64(&names));
}
