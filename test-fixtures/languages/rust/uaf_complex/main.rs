mod handle;

use handle::Handle;
use std::mem;
use std::ptr;

// `drop(h)` then `read(h)` — explicit-drop UAF.
fn use_after_drop(h: Handle) -> usize {
    drop(h);
    h.read()
}

// `mem::replace` swaps the value out; the old binding still in scope is dead.
fn use_after_replace(mut h: Handle) -> usize {
    let _old = mem::replace(&mut h, Handle::new(0));
    h.read()
}

// `mem::take` zeroes the original; reading after.
fn use_after_take(mut h: Handle) -> usize {
    let _stolen = mem::take(&mut h);
    h.read()
}

// `Box::from_raw` transfers ownership; using the raw pointer after is UAF.
unsafe fn use_after_into_raw(h: Box<Handle>) -> usize {
    let raw = Box::into_raw(h);
    let _owned = Box::from_raw(raw);
    (*raw).read()
}

// `ptr::drop_in_place` runs the destructor; subsequent access is UAF.
unsafe fn drop_in_place_then_read(h: Handle) -> usize {
    let p = &h as *const Handle;
    ptr::drop_in_place(p as *mut Handle);
    (*p).read()
}

fn main() {
    let h = Handle::new(1);
    let _ = use_after_drop(h);
    let h = Handle::new(2);
    let _ = use_after_replace(h);
    let h = Handle::new(3);
    let _ = use_after_take(h);
}
