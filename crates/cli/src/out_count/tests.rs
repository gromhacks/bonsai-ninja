use super::visible_byte_len;

#[test]
fn strips_sgr_color() {
    let s = "\x1b[38;2;96;156;156;1moutput\x1b[0m";
    assert_eq!(visible_byte_len(s), "output".len());
}

#[test]
fn keeps_plain_ascii() {
    assert_eq!(visible_byte_len("hello world\n"), "hello world\n".len());
}

#[test]
fn strips_osc_hyperlink() {
    let s = "\x1b]8;;https://x\x1b\\label\x1b]8;;\x1b\\";
    assert_eq!(visible_byte_len(s), "label".len());
}

#[test]
fn drops_carriage_return() {
    assert_eq!(visible_byte_len("a\rb\n"), 3); // 'a' + 'b' + '\n'
}
