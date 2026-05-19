use super::*;

#[test]
fn spanmap_basic() {
    let map = SpanMap::new("hello\nworld\n!");
    assert_eq!(map.line_col(0), LineCol { line: 1, column: 1 });
    assert_eq!(map.line_col(6), LineCol { line: 2, column: 1 });
    assert_eq!(map.line_col(12), LineCol { line: 3, column: 1 });
}

#[test]
fn span_order() {
    let f = FileId::new(0);
    let a = Span::new(f, 0, 5);
    let b = Span::new(f, 5, 10);
    assert!(a < b);
    assert_eq!(a.join(b), Span::new(f, 0, 10));
}
