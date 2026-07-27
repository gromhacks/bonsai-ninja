//! Cross-platform positioned I/O for immutable compiler relations.
//!
//! Positioned reads avoid a shared file cursor, so completed temporary
//! relations can be queried concurrently without a mutex or resident mirror.

use std::fs::File;
use std::io;

#[cfg(unix)]
pub(crate) fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
pub(crate) fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut total = 0usize;
    while total < buf.len() {
        let read = file.seek_read(&mut buf[total..], offset + total as u64)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "exact compiler relation ended before the indexed record",
            ));
        }
        total += read;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn read_exact_at(_file: &File, _offset: u64, _buf: &mut [u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "positioned exact-relation reads are unavailable on this platform",
    ))
}
