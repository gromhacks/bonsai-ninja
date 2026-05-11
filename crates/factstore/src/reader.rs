//! On-disk reader for fact-store files.
//!
//! Design: hot bookkeeping (header, string pool bytes, index) is
//! loaded eagerly into a `Box<[u8]>` at open time so lookups are
//! pure memory math. Payload bytes are read on demand via
//! `read_at`-style positioned reads — the OS page cache absorbs
//! repeat reads, so a hot working set effectively lives in kernel
//! memory without us having to mmap the file.
//!
//! Why not `memmap2`? The workspace lint `unsafe_code = "forbid"`
//! (Cargo.toml:110) cannot be overridden per-crate, and every
//! file-backed mmap entrypoint in `memmap2` is `unsafe`. Positioned
//! reads via `std::os::unix::fs::FileExt::read_exact_at` /
//! `std::os::windows::fs::FileExt::seek_read` are fully safe and
//! deliver the same access pattern: header-and-index resident,
//! payloads streamed through the OS page cache.
//!
//! The trade-off vs. real mmap is one `memcpy` per cold payload
//! lookup (kernel page → caller's buffer). The LRU layer in
//! `crate::cache` absorbs this on hot paths. If a future workload
//! demonstrates this matters, swapping in mmap is a localised
//! change behind the same `LookupHit` API.

use crate::error::{FactStoreError, FactStoreResult};
use crate::format::{Header, IndexEntry, FORMAT_VERSION, HEADER_SIZE, INDEX_ENTRY_SIZE};
use crate::string_pool::StringPoolView;
use std::fs::File;
use std::path::Path;

/// One looked-up entry.
///
/// `payload` is owned because the underlying bytes are read on demand
/// from disk (see module docs). Callers that want zero-copy semantics
/// should run their hot loop through [`crate::cache::FactCache`],
/// which keeps decoded values in process memory.
#[derive(Clone, Debug)]
pub struct LookupHit {
    /// Body hash recorded at write time. Lets callers detect that the
    /// key still exists but its underlying source has changed since
    /// the cache was written.
    pub body_hash: u64,
    /// Raw payload bytes, exactly as the writer encoded them.
    pub payload: Vec<u8>,
}

/// Read-only view of a fact-store file.
///
/// `Send + Sync`: the underlying `File` is shared by reference and
/// every read uses positioned I/O (no shared file cursor). The
/// resident bookkeeping (`header_bytes`, `index_bytes`,
/// `string_pool_bytes`) is immutable after open.
pub struct FactStoreReader {
    file: File,
    header: Header,
    /// Heap copy of the index section. Resident because we
    /// binary-search it on every lookup; staying out of the OS page
    /// cache saves a syscall per `get`.
    index_bytes: Box<[u8]>,
    /// Heap copy of the string pool bytes section. Resident for the
    /// same reason — every payload that references a `StrId` reads
    /// through this slice.
    string_pool_bytes: Box<[u8]>,
    /// Heap copy of the string pool offsets section.
    string_pool_offsets: Box<[u8]>,
}

impl std::fmt::Debug for FactStoreReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactStoreReader")
            .field("table_id", &self.header.table_id)
            .field("pipeline_hash", &format_args!("{:#x}", self.header.pipeline_hash))
            .field("entries", &self.header.index_count)
            .field("strings", &self.header.string_count)
            .field("payload_bytes", &self.header.payload_len)
            .finish()
    }
}

impl FactStoreReader {
    /// Open the fact store at `path`, validating the magic, version,
    /// table id, pipeline hash, and section bounds.
    ///
    /// `expected_table_id` and `expected_pipeline_hash` are caller-side
    /// invariants; mismatches surface as typed errors so callers can
    /// distinguish "the file was written for a different cache" from
    /// truly corrupt files.
    pub fn open(
        path: &Path,
        expected_table_id: u32,
        expected_pipeline_hash: u64,
    ) -> FactStoreResult<Self> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < HEADER_SIZE as u64 {
            return Err(FactStoreError::Truncated {
                expected: HEADER_SIZE as u64,
                actual: file_len,
            });
        }
        let mut header_buf = [0u8; HEADER_SIZE];
        read_exact_at(&file, 0, &mut header_buf)?;
        let header = Header::from_bytes(&header_buf).ok_or(FactStoreError::BadMagic)?;
        if header.format_version != FORMAT_VERSION {
            return Err(FactStoreError::VersionMismatch {
                file: header.format_version,
                expected: FORMAT_VERSION,
            });
        }
        if header.table_id != expected_table_id {
            return Err(FactStoreError::WrongTable {
                file: header.table_id,
                expected: expected_table_id,
            });
        }
        if header.pipeline_hash != expected_pipeline_hash {
            return Err(FactStoreError::PipelineMismatch {
                file: header.pipeline_hash,
                expected: expected_pipeline_hash,
            });
        }
        validate_section_bounds(&header, file_len)?;
        let (string_pool_bytes, string_pool_offsets) = load_string_pool(&file, &header)?;
        let index_bytes = load_index(&file, &header)?;
        validate_index_sorted_and_bounded(&header, &index_bytes)?;
        Ok(Self {
            file,
            header,
            index_bytes,
            string_pool_bytes,
            string_pool_offsets,
        })
    }

    /// Open with no caller-side invariants. Useful for tools that
    /// inspect a fact-store file without knowing what cache it
    /// belongs to. Still validates structural invariants and version.
    pub fn open_relaxed(path: &Path) -> FactStoreResult<Self> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < HEADER_SIZE as u64 {
            return Err(FactStoreError::Truncated {
                expected: HEADER_SIZE as u64,
                actual: file_len,
            });
        }
        let mut header_buf = [0u8; HEADER_SIZE];
        read_exact_at(&file, 0, &mut header_buf)?;
        let header = Header::from_bytes(&header_buf).ok_or(FactStoreError::BadMagic)?;
        if header.format_version != FORMAT_VERSION {
            return Err(FactStoreError::VersionMismatch {
                file: header.format_version,
                expected: FORMAT_VERSION,
            });
        }
        validate_section_bounds(&header, file_len)?;
        let (string_pool_bytes, string_pool_offsets) = load_string_pool(&file, &header)?;
        let index_bytes = load_index(&file, &header)?;
        validate_index_sorted_and_bounded(&header, &index_bytes)?;
        Ok(Self {
            file,
            header,
            index_bytes,
            string_pool_bytes,
            string_pool_offsets,
        })
    }

    /// Header decoded from the file.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Number of indexed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.header.index_count as usize
    }

    /// True iff the file holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.header.index_count == 0
    }

    /// Borrow the string pool. Free after open; cheap to call
    /// repeatedly. The view borrows from the resident bookkeeping
    /// buffers so its lifetime is tied to the reader.
    pub fn string_pool(&self) -> FactStoreResult<StringPoolView<'_>> {
        StringPoolView::new(
            &self.string_pool_bytes,
            &self.string_pool_offsets,
            self.header.string_count as u32,
        )
    }

    /// Look up the entry for `key`. Returns `None` if no entry has
    /// that key. O(log N) on the index size + one positioned read of
    /// the payload bytes.
    pub fn get(&self, key: u64) -> FactStoreResult<Option<LookupHit>> {
        let count = self.header.index_count as usize;
        let Some(row) = binary_search_index(&self.index_bytes, count, key) else {
            return Ok(None);
        };
        let entry = IndexEntry::from_bytes(
            &self.index_bytes[row * INDEX_ENTRY_SIZE..(row + 1) * INDEX_ENTRY_SIZE],
        )
        .ok_or(FactStoreError::BadIndexEntry { row })?;
        let mut buf = vec![0u8; entry.payload_len as usize];
        read_exact_at(&self.file, entry.payload_offset, &mut buf)?;
        Ok(Some(LookupHit {
            body_hash: entry.body_hash,
            payload: buf,
        }))
    }

    /// Iterate every `(key, body_hash, payload)` triple in index
    /// order (ascending by key). Each step reads one payload from
    /// disk; useful for migrating an old cache forward or for tools
    /// that dump the whole store, but not for the hot-query path.
    pub fn iter(&self) -> EntryIter<'_> {
        EntryIter {
            reader: self,
            cursor: 0,
        }
    }
}

impl<'r> IntoIterator for &'r FactStoreReader {
    type Item = FactStoreResult<(u64, LookupHit)>;
    type IntoIter = EntryIter<'r>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over every entry in the store. Ordered by key ascending.
pub struct EntryIter<'r> {
    reader: &'r FactStoreReader,
    cursor: usize,
}

impl<'r> Iterator for EntryIter<'r> {
    type Item = FactStoreResult<(u64, LookupHit)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.reader.len() {
            return None;
        }
        let row = self.cursor;
        self.cursor += 1;
        let Some(entry) = IndexEntry::from_bytes(
            &self.reader.index_bytes[row * INDEX_ENTRY_SIZE..(row + 1) * INDEX_ENTRY_SIZE],
        ) else {
            return Some(Err(FactStoreError::BadIndexEntry { row }));
        };
        let mut buf = vec![0u8; entry.payload_len as usize];
        if let Err(err) = read_exact_at(&self.reader.file, entry.payload_offset, &mut buf) {
            return Some(Err(err.into()));
        }
        Some(Ok((
            entry.key,
            LookupHit {
                body_hash: entry.body_hash,
                payload: buf,
            },
        )))
    }
}

/// Positioned `read_exact` shim. Avoids holding a shared file cursor
/// across threads and avoids `&mut self` on the reader.
#[cfg(unix)]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut total = 0usize;
    while total < buf.len() {
        let n = file.seek_read(&mut buf[total..], offset + total as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "factstore: unexpected EOF during positioned read",
            ));
        }
        total += n;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_exact_at(_file: &File, _offset: u64, _buf: &mut [u8]) -> std::io::Result<()> {
    // Other platforms (wasm, etc.) need their own positioned-read
    // adapter. The sidecar layer never targets those today.
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "factstore: positioned reads not implemented on this platform",
    ))
}

/// `(bytes_section, offsets_section)` pulled off disk into resident
/// heap copies. Both are immutable after open; readers borrow into
/// them when constructing a [`StringPoolView`].
type StringPoolBuffers = (Box<[u8]>, Box<[u8]>);

/// Pull the string pool's bytes + offsets sections off disk into
/// resident heap copies. Returns `(bytes, offsets)`.
fn load_string_pool(file: &File, header: &Header) -> FactStoreResult<StringPoolBuffers> {
    let bytes_len = header.string_pool_bytes_len as usize;
    let mut bytes = vec![0u8; bytes_len];
    if !bytes.is_empty() {
        read_exact_at(file, header.string_pool_offset, &mut bytes)?;
    }
    let offsets_len = (header.string_count as usize + 1) * 4;
    let mut offsets = vec![0u8; offsets_len];
    let offsets_offset = header.string_pool_offset + header.string_pool_bytes_len;
    read_exact_at(file, offsets_offset, &mut offsets)?;
    Ok((bytes.into_boxed_slice(), offsets.into_boxed_slice()))
}

/// Pull the index section off disk into a resident heap copy. The
/// caller will binary-search this on every `get`, so paying ~3 MB
/// per 100K entries up front beats one syscall per lookup.
fn load_index(file: &File, header: &Header) -> FactStoreResult<Box<[u8]>> {
    let len = header.index_count as usize * INDEX_ENTRY_SIZE;
    let mut buf = vec![0u8; len];
    if !buf.is_empty() {
        read_exact_at(file, header.index_offset, &mut buf)?;
    }
    Ok(buf.into_boxed_slice())
}

/// Verify every section the header points at fits inside the file.
fn validate_section_bounds(header: &Header, file_len: u64) -> FactStoreResult<()> {
    let bounds = [
        (
            header.string_pool_offset,
            header.string_pool_bytes_len,
            "string pool bytes",
        ),
        (
            header.string_pool_offset + header.string_pool_bytes_len,
            (header.string_count + 1) * 4,
            "string pool offsets",
        ),
        (
            header.index_offset,
            header.index_count * INDEX_ENTRY_SIZE as u64,
            "index",
        ),
        (header.payload_offset, header.payload_len, "payload"),
    ];
    for (offset, len, _name) in bounds {
        let end = offset.checked_add(len).ok_or(FactStoreError::Truncated {
            expected: u64::MAX,
            actual: file_len,
        })?;
        if end > file_len {
            return Err(FactStoreError::Truncated {
                expected: end,
                actual: file_len,
            });
        }
    }
    Ok(())
}

/// Verify the index is sorted ascending by key (the binary-search
/// invariant) and that every entry's payload range is inside the
/// declared payload section. O(N) on file open; constant per-lookup
/// afterwards.
fn validate_index_sorted_and_bounded(header: &Header, index_bytes: &[u8]) -> FactStoreResult<()> {
    let count = header.index_count as usize;
    if count == 0 {
        return Ok(());
    }
    let payload_section_end = header.payload_offset + header.payload_len;
    let mut prev_key = u64::MIN;
    for i in 0..count {
        let row = &index_bytes[i * INDEX_ENTRY_SIZE..(i + 1) * INDEX_ENTRY_SIZE];
        let entry = IndexEntry::from_bytes(row).ok_or(FactStoreError::BadIndexEntry { row: i })?;
        if i > 0 && entry.key < prev_key {
            return Err(FactStoreError::UnsortedIndex);
        }
        let payload_end =
            entry.payload_offset.checked_add(entry.payload_len as u64).ok_or(
                FactStoreError::BadIndexEntry { row: i },
            )?;
        if entry.payload_offset < header.payload_offset || payload_end > payload_section_end {
            return Err(FactStoreError::BadIndexEntry { row: i });
        }
        prev_key = entry.key;
    }
    Ok(())
}

/// Binary-search the index for `key`. Returns the row index on hit.
/// Reads only the 8-byte key prefix of each row it visits; payload
/// bytes are touched only after the match.
fn binary_search_index(index: &[u8], count: usize, key: u64) -> Option<usize> {
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let key_bytes = &index[mid * INDEX_ENTRY_SIZE..mid * INDEX_ENTRY_SIZE + 8];
        let mid_key = u64::from_le_bytes(key_bytes.try_into().ok()?);
        match mid_key.cmp(&key) {
            std::cmp::Ordering::Equal => return Some(mid),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::FactStoreWriter;

    fn write_test_store(path: &Path, table: u32, hash: u64, entries: &[(u64, u64, &[u8])]) {
        let mut w = FactStoreWriter::create(path, table, hash).expect("create");
        for &(key, body_hash, payload) in entries {
            w.add(key, body_hash, payload).expect("add");
        }
        w.finish().expect("finish");
    }

    #[test]
    fn open_roundtrips_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, 1, 0xCAFE, &[]);
        let r = FactStoreReader::open(&path, 1, 0xCAFE).expect("open");
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn get_returns_payload_for_known_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(
            &path,
            2,
            0xDEAD,
            &[(10, 100, b"ten"), (20, 200, b"twenty"), (30, 300, b"thirty")],
        );
        let r = FactStoreReader::open(&path, 2, 0xDEAD).expect("open");
        let twenty = r.get(20).expect("ok").expect("hit");
        assert_eq!(twenty.payload, b"twenty");
        assert_eq!(twenty.body_hash, 200);
        let ten = r.get(10).expect("ok").expect("hit");
        assert_eq!(ten.payload, b"ten");
        let thirty = r.get(30).expect("ok").expect("hit");
        assert_eq!(thirty.payload, b"thirty");
    }

    #[test]
    fn get_returns_none_for_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, 0, 0, &[(1, 0, b"a"), (3, 0, b"c"), (5, 0, b"e")]);
        let r = FactStoreReader::open(&path, 0, 0).expect("open");
        assert!(r.get(0).expect("ok").is_none());
        assert!(r.get(2).expect("ok").is_none());
        assert!(r.get(4).expect("ok").is_none());
        assert!(r.get(6).expect("ok").is_none());
        assert_eq!(r.get(3).expect("ok").expect("hit").payload, b"c");
    }

    #[test]
    fn open_rejects_wrong_table_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, 1, 0xCAFE, &[]);
        let err = FactStoreReader::open(&path, 99, 0xCAFE).expect_err("must reject");
        match err {
            FactStoreError::WrongTable { file, expected } => {
                assert_eq!(file, 1);
                assert_eq!(expected, 99);
            }
            other => panic!("expected WrongTable, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_wrong_pipeline_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, 1, 0xCAFE, &[]);
        let err = FactStoreReader::open(&path, 1, 0xBEEF).expect_err("must reject");
        match err {
            FactStoreError::PipelineMismatch { file, expected } => {
                assert_eq!(file, 0xCAFE);
                assert_eq!(expected, 0xBEEF);
            }
            other => panic!("expected PipelineMismatch, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        std::fs::write(&path, vec![0u8; HEADER_SIZE]).expect("write zeros");
        let err = FactStoreReader::open(&path, 0, 0).expect_err("must reject");
        assert!(matches!(err, FactStoreError::BadMagic));
    }

    #[test]
    fn open_rejects_truncated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        std::fs::write(&path, vec![0u8; HEADER_SIZE - 1]).expect("write");
        let err = FactStoreReader::open(&path, 0, 0).expect_err("must reject");
        assert!(matches!(err, FactStoreError::Truncated { .. }));
    }

    #[test]
    fn iter_visits_entries_in_key_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(
            &path,
            0,
            0,
            &[(30, 0, b"c"), (10, 0, b"a"), (20, 0, b"b")],
        );
        let r = FactStoreReader::open(&path, 0, 0).expect("open");
        let collected: Vec<(u64, Vec<u8>)> = r
            .iter()
            .map(|item| {
                let (k, hit) = item.expect("ok");
                (k, hit.payload)
            })
            .collect();
        assert_eq!(
            collected,
            vec![
                (10, b"a".to_vec()),
                (20, b"b".to_vec()),
                (30, b"c".to_vec()),
            ]
        );
    }

    #[test]
    fn string_pool_view_is_accessible_through_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let mut w = FactStoreWriter::create(&path, 0, 0).expect("create");
        let a = w.intern("hello");
        let b = w.intern("world");
        w.add(1, 0, &[]).expect("add");
        w.finish().expect("finish");
        let r = FactStoreReader::open(&path, 0, 0).expect("open");
        let pool = r.string_pool().expect("pool");
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.get(a), Some("hello"));
        assert_eq!(pool.get(b), Some("world"));
    }

    #[test]
    fn binary_search_locates_first_and_last() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let entries: Vec<(u64, u64, &[u8])> =
            (0..1000u64).map(|i| (i * 2, i, b"x" as &[u8])).collect();
        write_test_store(&path, 0, 0, &entries);
        let r = FactStoreReader::open(&path, 0, 0).expect("open");
        assert_eq!(r.get(0).expect("ok").unwrap().body_hash, 0);
        assert_eq!(r.get(1998).expect("ok").unwrap().body_hash, 999);
        assert!(r.get(1).expect("ok").is_none());
        assert!(r.get(1999).expect("ok").is_none());
        assert!(r.get(2000).expect("ok").is_none());
    }

    #[test]
    fn parallel_reads_are_safe() {
        // Verify Send + Sync — many threads can hit `get` against
        // the same reader. The positioned-read API does not share a
        // file cursor, so this should be deadlock- and race-free.
        use std::sync::Arc;
        use std::thread;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let entries: Vec<(u64, u64, &[u8])> =
            (0..256u64).map(|i| (i, i, b"payload" as &[u8])).collect();
        write_test_store(&path, 0, 0, &entries);
        let r = Arc::new(FactStoreReader::open(&path, 0, 0).expect("open"));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let r = Arc::clone(&r);
            handles.push(thread::spawn(move || {
                for k in 0..256u64 {
                    let hit = r.get(k).expect("ok").expect("hit");
                    assert_eq!(hit.body_hash, k);
                    assert_eq!(hit.payload, b"payload");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
    }
}
