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
    pub fn open(path: &Path, expected_table_id: u32, expected_pipeline_hash: u64) -> FactStoreResult<Self> {
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

    /// Return whether `key` is present in the validated on-disk index without
    /// reading or allocating its payload. Useful for cheap sidecar layout
    /// validation before a command decides whether it needs to hydrate facts.
    #[must_use]
    pub fn contains_key(&self, key: u64) -> bool {
        binary_search_index(&self.index_bytes, self.header.index_count as usize, key).is_some()
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
        let entry =
            IndexEntry::from_bytes(&self.index_bytes[row * INDEX_ENTRY_SIZE..(row + 1) * INDEX_ENTRY_SIZE])
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
    // Every `offset`/`len` below is a raw `u64` read straight off disk, so
    // a corrupt or hostile header could overflow these derived sizes. Use
    // saturating arithmetic for the section-relative offset and length so an
    // out-of-range field pins to `u64::MAX` and is caught by the `end >
    // file_len` check below rather than wrapping to a small value that
    // sneaks a malformed file past validation (release) or panics (debug).
    let bounds = [
        (
            header.string_pool_offset,
            header.string_pool_bytes_len,
            "string pool bytes",
        ),
        (
            header
                .string_pool_offset
                .saturating_add(header.string_pool_bytes_len),
            (header.string_count.saturating_add(1)).saturating_mul(4),
            "string pool offsets",
        ),
        (
            header.index_offset,
            header.index_count.saturating_mul(INDEX_ENTRY_SIZE as u64),
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
    // Header fields are read off disk; guard the derived end against
    // overflow rather than wrapping (debug panic / silent bypass in release).
    let payload_section_end =
        header
            .payload_offset
            .checked_add(header.payload_len)
            .ok_or(FactStoreError::Truncated {
                expected: u64::MAX,
                actual: header.payload_offset,
            })?;
    let mut prev_key = u64::MIN;
    for i in 0..count {
        let row = &index_bytes[i * INDEX_ENTRY_SIZE..(i + 1) * INDEX_ENTRY_SIZE];
        let entry = IndexEntry::from_bytes(row).ok_or(FactStoreError::BadIndexEntry { row: i })?;
        if i > 0 {
            if entry.key < prev_key {
                return Err(FactStoreError::UnsortedIndex);
            }
            if entry.key == prev_key {
                return Err(FactStoreError::DuplicateKey(entry.key));
            }
        }
        let payload_end = entry
            .payload_offset
            .checked_add(entry.payload_len as u64)
            .ok_or(FactStoreError::BadIndexEntry { row: i })?;
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
#[path = "reader_tests.rs"]
mod tests;
