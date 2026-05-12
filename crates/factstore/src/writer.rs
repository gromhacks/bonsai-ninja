//! Streaming, channel-backed writer for fact stores.
//!
//! Usage shape:
//!
//! ```ignore
//! let writer = FactStoreWriter::create(&path, table_id, pipeline_hash)?;
//! let str_id = writer.intern("hello");          // shared via &writer
//! writer.add(key, body_hash, &payload_bytes)?;  // shared via &writer
//! // ... many concurrent intern/add calls from rayon workers ...
//! writer.finish()?;
//! ```
//!
//! ## Design
//!
//! Workers call `add(&self, ...)` which **pushes** the entry to a
//! `crossbeam_channel::Sender`. A single dedicated writer thread,
//! spawned at `create` time, owns the tmp file and drains the channel
//! sequentially: append payload bytes to disk, record an index row.
//!
//! Why this instead of `Mutex<FactStoreWriter>` with a fallible
//! `add(&mut self)`:
//!
//! - File I/O happens off the rayon worker hot path. Workers spend
//!   their time computing + encoding, not waiting for `flush` or
//!   `write_all`.
//! - The channel send is lock-free (crossbeam unbounded MPMC) so
//!   workers don't serialize on a Mutex acquire.
//! - `add(&self)` lets the writer be shared as `&FactStoreWriter`
//!   directly through `par_iter().for_each(|f| writer.add(...))` —
//!   no `Mutex<FactStoreWriter>` wrapper, no per-iteration lock.
//!
//! String interning still goes through a small `parking_lot::Mutex`
//! around the `StringPoolBuilder` — interning is a couple hash-table
//! ops, much shorter than file I/O, and the lock is uncontended in
//! practice.
//!
//! ## Atomic-rename invariant
//!
//! The writer thread holds an open tmp file beside `target`. On
//! `finish`:
//! 1. Workers stop calling `add` (the caller's responsibility).
//! 2. `finish` posts a `WriteCmd::Finish` carrying the in-flight
//!    string-pool data + a one-shot reply channel.
//! 3. The writer thread drains any remaining `Entry` commands,
//!    appends the string pool + sorted index after the streamed
//!    payloads, seeks to byte 0 and writes the real header,
//!    `fsync`s, atomic-renames over `target`, `fsync`s the parent
//!    dir, and replies through the one-shot.
//! 4. `finish` joins the thread.
//!
//! On drop without `finish`, the channel closes (sender drops),
//! the writer thread sees `Disconnected`, removes the tmp file,
//! and exits. Drop joins the thread so the OS handle is released
//! synchronously.

use crate::error::{FactStoreError, FactStoreResult};
use crate::format::{Header, IndexEntry, FORMAT_VERSION, HEADER_SIZE, MAGIC};
use crate::string_pool::{StrId, StringPoolBuilder};
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;

/// Monotonic counter used to disambiguate temp files when many
/// writers race for the same target path within a single process.
static WRITER_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Streaming writer for a fact-store file.
///
/// Sharable as `&FactStoreWriter` from rayon workers — `add` and
/// `intern` are `&self` operations that delegate to a background
/// writer thread (channel send) and a small mutex (string pool)
/// respectively. There is no per-call lock on the I/O path, so
/// thousands of concurrent `add` calls do not serialise on each
/// other.
pub struct FactStoreWriter {
    string_pool: parking_lot::Mutex<StringPoolBuilder>,
    sender: Sender<WriteCmd>,
    /// Joined by [`Self::finish`] (or `Drop` if `finish` is skipped)
    /// to release the OS thread handle synchronously. `Option` so
    /// `finish` can take it out of the field; `Mutex` so `&self` Drop
    /// can do the same on the cleanup path.
    writer_thread: parking_lot::Mutex<Option<JoinHandle<()>>>,
    /// Reply channel kept around so [`Self::finish`] can recv() the
    /// writer thread's final result. Boxed in an `Option` so finish
    /// can take exclusive ownership.
    finish_reply: parking_lot::Mutex<Option<Receiver<FactStoreResult<usize>>>>,
}

impl std::fmt::Debug for FactStoreWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactStoreWriter")
            .field("strings", &self.string_pool.lock().len())
            .field("queued", &self.sender.len())
            .finish()
    }
}

/// Command shipped from worker → writer thread.
enum WriteCmd {
    /// Append one entry's payload to the streamed file and record an
    /// index row.
    Entry {
        key: u64,
        body_hash: u64,
        payload: Vec<u8>,
    },
    /// Drain queue, finalize the file (string pool, index, header,
    /// fsync, rename), and reply with the entry count.
    Finish {
        string_bytes: Vec<u8>,
        string_offsets: Vec<u8>,
        string_count: u64,
        reply: Sender<FactStoreResult<usize>>,
    },
}

struct PendingIndexEntry {
    key: u64,
    body_hash: u64,
    payload_offset: u64,
    payload_len: u32,
}

impl FactStoreWriter {
    /// Open a writer that streams payloads into a temp file next to
    /// `target` and atomically renames on [`Self::finish`]. Spawns a
    /// dedicated writer thread up front; the calling thread does no
    /// file I/O.
    pub fn create(target: &Path, table_id: u32, pipeline_hash: u64) -> FactStoreResult<Self> {
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp_path = unique_tmp_path(target);
        // Open the tmp file on the calling thread first so any
        // permission / EEXIST error surfaces synchronously to the
        // caller rather than silently in the background thread.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&tmp_path)?;
        let target_path = target.to_path_buf();
        let (sender, receiver) = unbounded::<WriteCmd>();
        let (finish_reply_tx, finish_reply_rx) = bounded::<FactStoreResult<usize>>(1);
        let handle = std::thread::Builder::new()
            .name("factstore-writer".to_string())
            .spawn(move || {
                let outcome =
                    run_writer_thread(file, receiver, table_id, pipeline_hash, tmp_path, target_path);
                if let Err(err) = outcome {
                    // The Finish path already replies through the
                    // one-shot. This branch covers a write error in
                    // an Entry command, where we never receive a
                    // Finish — surface the error via the reply
                    // channel anyway so `finish()` can return it.
                    let _ = finish_reply_tx.send(Err(err));
                }
            })?;
        Ok(Self {
            string_pool: parking_lot::Mutex::new(StringPoolBuilder::new()),
            sender,
            writer_thread: parking_lot::Mutex::new(Some(handle)),
            finish_reply: parking_lot::Mutex::new(Some(finish_reply_rx)),
        })
    }

    /// Pre-allocate hints for the string pool. Useful when the caller
    /// can predict the rough scale of the cache.
    pub fn create_with_capacity(
        target: &Path,
        table_id: u32,
        pipeline_hash: u64,
        _entries: usize,
        string_bytes: usize,
        strings: usize,
    ) -> FactStoreResult<Self> {
        let writer = Self::create(target, table_id, pipeline_hash)?;
        *writer.string_pool.lock() = StringPoolBuilder::with_capacity(string_bytes, strings);
        Ok(writer)
    }

    /// Intern a string into the writer's pool and return its id.
    /// Locks a small mutex around the pool. Concurrent callers
    /// serialize briefly here but the operation is cheap.
    pub fn intern(&self, s: &str) -> StrId {
        self.string_pool.lock().intern(s)
    }

    /// Append one entry to the writer. The payload is sent to the
    /// writer thread via the channel — this call does no file I/O
    /// and acquires no Mutex.
    pub fn add(&self, key: u64, body_hash: u64, payload: &[u8]) -> FactStoreResult<()> {
        if u32::try_from(payload.len()).is_err() {
            return Err(FactStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds 4 GiB",
            )));
        }
        // `crossbeam_channel::Sender::send` returns Err only when the
        // receiver has been dropped (writer thread exited). That's
        // a contract violation — the writer was finished/dropped
        // while another thread was still calling `add`.
        self.sender
            .send(WriteCmd::Entry {
                key,
                body_hash,
                payload: payload.to_vec(),
            })
            .map_err(|_| {
                FactStoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "factstore writer thread is no longer accepting entries",
                ))
            })
    }

    /// Number of unique strings interned so far.
    #[must_use]
    pub fn string_count(&self) -> usize {
        self.string_pool.lock().len()
    }

    /// Borrow the in-progress string pool. Holds the mutex for the
    /// duration of the closure.
    pub fn with_string_pool<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&StringPoolBuilder) -> R,
    {
        f(&self.string_pool.lock())
    }

    /// Finalize the writer: signal the writer thread to drain any
    /// pending entries, append the string pool + index, patch the
    /// header, fsync, atomic-rename over `target`, fsync the parent
    /// dir. Returns the number of index rows that landed in the file.
    pub fn finish(mut self) -> FactStoreResult<usize> {
        // Take owned copies of the internal state. We can't
        // destructure `self` directly (it implements `Drop`), so
        // we swap each field out via `mem::take` / `lock().take()`.
        // The post-take `self` falls out of scope at the end of this
        // method; `Drop` then sees `None`/`empty` fields and is a
        // no-op.
        let pool = std::mem::take(&mut *self.string_pool.lock());
        let string_bytes = pool.bytes().to_vec();
        let string_offsets = pool.offsets_bytes();
        let string_count = pool.len() as u64;

        let reply_rx_panic_safety = self.finish_reply.lock().take().ok_or_else(|| {
            FactStoreError::Io(std::io::Error::other(
                "factstore writer reply channel already consumed",
            ))
        })?;
        let handle = self.writer_thread.lock().take().ok_or_else(|| {
            FactStoreError::Io(std::io::Error::other("factstore writer thread already joined"))
        })?;

        // Build a fresh oneshot for the Finish command's reply.
        let (reply_tx, owned_reply_rx) = bounded::<FactStoreResult<usize>>(1);
        self.sender
            .send(WriteCmd::Finish {
                string_bytes,
                string_offsets,
                string_count,
                reply: reply_tx,
            })
            .map_err(|_| {
                FactStoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "factstore writer thread exited before finish",
                ))
            })?;
        // Replace the input sender with a disconnected dummy so the
        // real channel closes once our Finish is consumed. Without
        // this the writer thread would block on recv() after
        // processing Finish and never exit.
        let (dummy_tx, _dummy_rx) = unbounded::<WriteCmd>();
        let real_sender = std::mem::replace(&mut self.sender, dummy_tx);
        drop(real_sender);

        // Wait for the writer thread's reply on the owned oneshot;
        // if that one fires Err (writer thread exited without
        // replying on our channel — panic or earlier write error),
        // fall back to the panic-safety reply set up at `create`.
        let result: FactStoreResult<usize> = match owned_reply_rx.recv() {
            Ok(res) => res,
            Err(_) => reply_rx_panic_safety.recv().unwrap_or_else(|_| {
                Err(FactStoreError::Io(std::io::Error::other(
                    "factstore writer thread exited without reply",
                )))
            }),
        };

        handle
            .join()
            .map_err(|_| FactStoreError::Io(std::io::Error::other("factstore writer thread panicked")))?;
        result
    }
}

impl Drop for FactStoreWriter {
    fn drop(&mut self) {
        // If `finish` was called, `writer_thread` is `None` here and
        // this branch is a no-op cleanup.
        //
        // If `finish` wasn't called (panic, early return), close the
        // channel by replacing the sender with a disconnected dummy.
        // The writer thread sees `Disconnected`, removes the tmp
        // file, and exits. Then we join the handle so the OS thread
        // resource releases synchronously.
        if let Some(handle) = self.writer_thread.lock().take() {
            let (dummy_tx, _dummy_rx) = unbounded::<WriteCmd>();
            let real_sender = std::mem::replace(&mut self.sender, dummy_tx);
            drop(real_sender);
            let _ = handle.join();
        }
    }
}

/// Writer-thread main loop.
fn run_writer_thread(
    file: File,
    receiver: Receiver<WriteCmd>,
    table_id: u32,
    pipeline_hash: u64,
    tmp_path: PathBuf,
    target_path: PathBuf,
) -> FactStoreResult<()> {
    let mut buf = BufWriter::new(file);
    // Reserve the header. We could `set_len` instead but writing
    // explicit zeros keeps the file deterministic if the process is
    // killed mid-stream.
    buf.write_all(&[0u8; HEADER_SIZE])?;

    let mut entries: Vec<PendingIndexEntry> = Vec::new();
    let mut next_payload_offset: u64 = HEADER_SIZE as u64;

    loop {
        match receiver.recv() {
            Ok(WriteCmd::Entry {
                key,
                body_hash,
                payload,
            }) => {
                let payload_len = u32::try_from(payload.len()).map_err(|_| {
                    FactStoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "payload exceeds 4 GiB",
                    ))
                })?;
                buf.write_all(&payload)?;
                entries.push(PendingIndexEntry {
                    key,
                    body_hash,
                    payload_offset: next_payload_offset,
                    payload_len,
                });
                next_payload_offset += payload.len() as u64;
            }
            Ok(WriteCmd::Finish {
                string_bytes,
                string_offsets,
                string_count,
                reply,
            }) => {
                let result = finalize_writer(
                    buf,
                    entries,
                    next_payload_offset,
                    string_bytes,
                    string_offsets,
                    string_count,
                    table_id,
                    pipeline_hash,
                    &tmp_path,
                    &target_path,
                );
                let _ = reply.send(result);
                return Ok(());
            }
            Err(_) => {
                // Channel closed without Finish — caller dropped the
                // writer. Cleanup tmp file.
                drop(buf);
                let _ = std::fs::remove_file(&tmp_path);
                return Ok(());
            }
        }
    }
}

/// Append the string pool + index, patch the header, fsync,
/// atomic-rename, fsync parent dir. Consumes the buffered file.
#[allow(clippy::too_many_arguments)]
fn finalize_writer(
    buf: BufWriter<File>,
    mut entries: Vec<PendingIndexEntry>,
    payload_section_end: u64,
    string_bytes: Vec<u8>,
    string_offsets: Vec<u8>,
    string_count: u64,
    table_id: u32,
    pipeline_hash: u64,
    tmp_path: &Path,
    target_path: &Path,
) -> FactStoreResult<usize> {
    // Sort by key for binary-search lookup at read time.
    entries.sort_by_key(|e| e.key);

    let payload_section_offset = HEADER_SIZE as u64;
    let payload_section_len = payload_section_end - payload_section_offset;

    let string_pool_offset = payload_section_end;
    let string_pool_bytes_len = string_bytes.len() as u64;

    let mut buf = buf;
    buf.write_all(&string_bytes)?;
    buf.write_all(&string_offsets)?;

    let index_offset = string_pool_offset + string_pool_bytes_len + string_offsets.len() as u64;
    let index_count = entries.len() as u64;
    for entry in &entries {
        let on_disk = IndexEntry {
            key: entry.key,
            body_hash: entry.body_hash,
            payload_offset: entry.payload_offset,
            payload_len: entry.payload_len,
            reserved: 0,
        };
        buf.write_all(&on_disk.to_bytes())?;
    }

    // Flush the BufWriter and reclaim the underlying File so we can
    // seek back to byte 0 and patch the header.
    let mut file = buf
        .into_inner()
        .map_err(|err| FactStoreError::Io(err.into_error()))?;
    let header = Header {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        table_id,
        pipeline_hash,
        string_pool_offset,
        string_pool_bytes_len,
        string_count,
        index_offset,
        index_count,
        payload_offset: payload_section_offset,
        payload_len: payload_section_len,
        reserved: [0; 8],
    };
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header.to_bytes())?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(tmp_path, target_path)?;
    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(index_count as usize)
}

/// Build a unique-per-process temp path next to `target`. Callers
/// that race for the same `target` will not collide because the
/// counter advances for every call.
fn unique_tmp_path(target: &Path) -> PathBuf {
    let counter = WRITER_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut path = target.to_path_buf();
    if let Some(filename) = target.file_name() {
        let mut full = OsString::from(filename);
        full.push(".tmp.");
        full.push(pid.to_string());
        full.push(".");
        full.push(counter.to_string());
        path.set_file_name(full);
    } else {
        let mut name = OsString::from(".factstore-tmp-");
        name.push(pid.to_string());
        name.push("-");
        name.push(counter.to_string());
        path.set_file_name(name);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Header;
    use crate::reader::FactStoreReader;

    #[test]
    fn empty_writer_emits_a_valid_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("v.bin");
        let writer = FactStoreWriter::create(&target, 7, 0xCAFE).expect("create");
        let written = writer.finish().expect("finish");
        assert_eq!(written, 0);
        let bytes = std::fs::read(&target).expect("read");
        let header = Header::from_bytes(&bytes).expect("magic + len OK");
        assert_eq!(header.format_version, FORMAT_VERSION);
        assert_eq!(header.table_id, 7);
        assert_eq!(header.pipeline_hash, 0xCAFE);
        assert_eq!(header.string_count, 0);
        assert_eq!(header.index_count, 0);
        assert_eq!(header.payload_len, 0);
        assert_eq!(header.payload_offset, HEADER_SIZE as u64);
    }

    #[test]
    fn entries_are_sorted_by_key_ascending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("v.bin");
        let w = FactStoreWriter::create(&target, 0, 0).expect("create");
        w.add(30, 0, b"thirty").expect("add");
        w.add(10, 0, b"ten").expect("add");
        w.add(20, 0, b"twenty").expect("add");
        w.finish().expect("finish");
        let r = FactStoreReader::open(&target, 0, 0).expect("open");
        let mut keys: Vec<u64> = r.iter().map(|item| item.expect("ok").0).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec![10, 20, 30]);
    }

    #[test]
    fn finish_creates_file_at_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("v.bin");
        let w = FactStoreWriter::create(&target, 1, 0xABCD).expect("create");
        w.add(42, 0xDEAD, b"hello").expect("add");
        w.finish().expect("finish");
        assert!(target.exists());
        let r = FactStoreReader::open(&target, 1, 0xABCD).expect("open");
        let hit = r.get(42).expect("ok").expect("hit");
        assert_eq!(hit.payload, b"hello");
        assert_eq!(hit.body_hash, 0xDEAD);
    }

    #[test]
    fn finish_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("nested/sub/dir/v.bin");
        let w = FactStoreWriter::create(&target, 0, 0).expect("create");
        w.finish().expect("finish");
        assert!(target.exists());
    }

    #[test]
    fn drop_without_finish_cleans_up_tmp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("v.bin");
        {
            let w = FactStoreWriter::create(&target, 0, 0).expect("create");
            w.add(1, 0, b"abandoned").expect("add");
            // dropped here without finish — tmp should be cleaned
        }
        // Give the writer thread a brief moment to handle the
        // channel-closed signal and remove the tmp file. (The Drop
        // impl joins, so this should already be synchronous, but the
        // test doesn't fight the OS scheduler if it isn't.)
        std::thread::sleep(std::time::Duration::from_millis(50));
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "no orphan files should remain, got {entries:?}"
        );
    }

    #[test]
    fn intern_ids_are_stable_and_dedup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("v.bin");
        let w = FactStoreWriter::create(&target, 0, 0).expect("create");
        let a = w.intern("foo");
        let b = w.intern("bar");
        let a2 = w.intern("foo");
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert_eq!(w.string_count(), 2);
        w.add(0, 0, &[]).expect("add");
        w.finish().expect("finish");
        let r = FactStoreReader::open(&target, 0, 0).expect("open");
        let pool = r.string_pool().expect("pool");
        assert_eq!(pool.get(a), Some("foo"));
        assert_eq!(pool.get(b), Some("bar"));
    }

    #[test]
    fn payload_offsets_in_index_are_absolute_and_sequential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("v.bin");
        let w = FactStoreWriter::create(&target, 0, 0).expect("create");
        w.add(1, 0, b"AAAA").expect("add");
        w.add(2, 0, b"BBBBBB").expect("add");
        w.add(3, 0, b"CCCCCCCC").expect("add");
        w.finish().expect("finish");
        let r = FactStoreReader::open(&target, 0, 0).expect("open");
        let header = r.header();
        assert_eq!(header.payload_offset, HEADER_SIZE as u64);
        assert_eq!(header.payload_len, 4 + 6 + 8);
        assert_eq!(r.get(1).expect("ok").unwrap().payload, b"AAAA");
        assert_eq!(r.get(2).expect("ok").unwrap().payload, b"BBBBBB");
        assert_eq!(r.get(3).expect("ok").unwrap().payload, b"CCCCCCCC");
    }

    #[test]
    fn unique_tmp_paths_dont_collide() {
        let target = Path::new("/tmp/store.bin");
        let a = unique_tmp_path(target);
        let b = unique_tmp_path(target);
        assert_ne!(a, b);
        assert_eq!(a.parent(), target.parent());
    }

    #[test]
    fn concurrent_adds_under_shared_ref_are_serialised_correctly() {
        // Verify that calling `add(&self)` from many threads yields
        // a fact-store file with the exact set of entries written —
        // proving that the channel handoff to the writer thread
        // preserves all sends and the writer drains them in order.
        use std::sync::Arc;
        use std::thread;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("v.bin");
        let writer = Arc::new(FactStoreWriter::create(&target, 0, 0).expect("create"));
        let mut handles = Vec::new();
        for tid in 0u64..8 {
            let w = Arc::clone(&writer);
            handles.push(thread::spawn(move || {
                for k in 0..32u64 {
                    w.add(tid * 100 + k, 0, &k.to_le_bytes()).expect("add");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        let writer = Arc::try_unwrap(writer).expect("only owner");
        let written = writer.finish().expect("finish");
        assert_eq!(written, 8 * 32);
        let r = FactStoreReader::open(&target, 0, 0).expect("open");
        for tid in 0u64..8 {
            for k in 0..32u64 {
                let key = tid * 100 + k;
                let hit = r.get(key).expect("ok").expect("hit");
                let recovered = u64::from_le_bytes(hit.payload[..8].try_into().unwrap());
                assert_eq!(recovered, k);
            }
        }
    }
}

