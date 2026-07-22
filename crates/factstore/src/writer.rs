//! Streaming, channel-backed writer for fact stores.
//!
//! Usage shape:
//!
//! ```ignore
//! let writer = FactStoreWriter::create(&path, table_id, pipeline_hash)?;
//! let str_id = writer.intern("hello");          // shared via &writer
//! writer.add(key, body_hash, &payload_bytes)?;  // shared via &writer
//! writer.add_owned(key, body_hash, encoded_vec)?; // transfers an owned buffer
//! // ... many concurrent intern/add calls from rayon workers ...
//! writer.finish()?;
//! ```
//!
//! ## Design
//!
//! Workers call `add(&self, ...)` or `add_owned(&self, ...)` to hand
//! entries to a bounded `crossbeam_channel::Sender`. A single dedicated
//! writer thread, spawned at `create` time, owns the tmp file and drains
//! the channel sequentially: append payload bytes to disk, record an
//! index row. The bounded queue applies backpressure when storage falls
//! behind serialization instead of retaining every encoded payload in
//! memory. Entries are never dropped or truncated.
//!
//! Why this instead of `Mutex<FactStoreWriter>` with a fallible
//! `add(&mut self)`:
//!
//! - File I/O happens off the rayon worker hot path. Workers spend
//!   their time computing + encoding, not waiting for `flush` or
//!   `write_all`.
//! - The channel handoff has no application-level I/O mutex. Producers
//!   wait only when the small pipeline buffer is full, which keeps peak
//!   payload memory bounded.
//! - `add(&self)` and `add_owned(&self)` let the writer be shared as
//!   `&FactStoreWriter`
//!   directly through `par_iter().for_each(|f| writer.add(...))` —
//!   no `Mutex<FactStoreWriter>` wrapper, no per-iteration lock.
//! - `add_owned` moves an already-serialized `Vec<u8>` into the writer
//!   thread without cloning it. `add` remains the borrowed compatibility
//!   API and performs one copy before delegating to `add_owned`.
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
use std::sync::Arc;
use std::thread::JoinHandle;

/// Monotonic counter used to disambiguate temp files when many
/// writers race for the same target path within a single process.
static WRITER_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Streaming writer for a fact-store file.
///
/// Sharable as `&FactStoreWriter` from rayon workers — `add`,
/// `add_owned`, and `intern` are `&self` operations that delegate to
/// a background writer thread (bounded channel send) and a small mutex
/// (string pool) respectively. There is no per-call application mutex
/// on the I/O path; a producer waits only when the bounded pipeline is
/// full.
pub struct FactStoreWriter {
    string_pool: parking_lot::Mutex<StringPoolBuilder>,
    sender: Sender<WriteCmd>,
    /// Byte-weighted backpressure shared with every producer. The channel's
    /// item bound alone is insufficient because one encoded graph can be
    /// orders of magnitude larger than another.
    byte_budget: Arc<ByteBudget>,
    /// A streamed entry may own an arbitrarily large compiler artifact inside
    /// its encoder closure. Serialize these calls so concurrent producers
    /// cannot queue several such artifacts outside the byte-accounted payload
    /// pipeline.
    stream_serial: parking_lot::Mutex<()>,
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

/// A prepared FactStore payload file that can be filled before the final
/// table metadata is known.
///
/// Compiler pipelines use this as an object-file staging area: exact payload
/// entries are appended once, may be read back by the compiler while later
/// passes run, and are finally adopted by [`FactStoreWriter`] without copying
/// the complete payload section through userspace again. The file starts with
/// a reserved FactStore header and is removed automatically unless ownership
/// is transferred to [`FactStoreWriter::create_from_prepared`].
#[derive(Debug)]
pub struct PreparedFactStorePayload {
    file: Option<File>,
    tmp_path: Option<PathBuf>,
}

/// One already-written entry inside a [`PreparedFactStorePayload`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PreparedFactStoreEntry {
    /// Lookup key for the final FactStore index.
    pub key: u64,
    /// Content or schema hash associated with the payload.
    pub body_hash: u64,
    /// Absolute byte offset inside the prepared file.
    pub payload_offset: u64,
    /// Encoded payload length.
    pub payload_len: u32,
}

impl PreparedFactStorePayload {
    /// Create a temporary prepared payload on the host's filesystem-backed
    /// temporary directory.
    ///
    /// Final adoption relocates it beside the destination before publication.
    /// If the temporary directory is on another filesystem, relocation falls
    /// back to an exact file copy; this affects performance only, never facts.
    pub fn create() -> FactStoreResult<Self> {
        let seed = std::env::temp_dir().join("bonsai-factstore-payload");
        Self::create_near(&seed)
    }

    /// Create a prepared payload beside its eventual FactStore target.
    ///
    /// Large compiler spools should prefer this constructor so the staging
    /// file is guaranteed to use the destination filesystem rather than a
    /// potentially memory-backed operating-system temporary directory.
    pub fn create_near(target: &Path) -> FactStoreResult<Self> {
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp_path = unique_tmp_path(target);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(&[0u8; HEADER_SIZE])?;
        Ok(Self {
            file: Some(file),
            tmp_path: Some(tmp_path),
        })
    }

    /// Append one encoded payload and return its absolute file range.
    ///
    /// The 4 GiB limit is the FactStore per-entry wire limit, not an analysis
    /// budget. Callers split larger relations into complete keyed chunks.
    pub fn append(&mut self, payload: &[u8]) -> FactStoreResult<(u64, u32)> {
        let payload_len = u32::try_from(payload.len()).map_err(|_| {
            FactStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds 4 GiB",
            ))
        })?;
        let file = self.file.as_mut().ok_or_else(|| {
            FactStoreError::Io(std::io::Error::other(
                "prepared FactStore payload was already consumed",
            ))
        })?;
        let payload_offset = file.seek(SeekFrom::End(0))?;
        file.write_all(payload)?;
        Ok((payload_offset, payload_len))
    }

    /// Clone the prepared file handle for positioned compiler reads.
    pub fn try_clone_file(&self) -> FactStoreResult<File> {
        self.file
            .as_ref()
            .ok_or_else(|| {
                FactStoreError::Io(std::io::Error::other(
                    "prepared FactStore payload was already consumed",
                ))
            })?
            .try_clone()
            .map_err(Into::into)
    }

    fn relocate(mut self, target: &Path) -> FactStoreResult<(File, PathBuf, u64)> {
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let source_path = self.tmp_path.take().ok_or_else(|| {
            FactStoreError::Io(std::io::Error::other(
                "prepared FactStore payload path was already consumed",
            ))
        })?;
        let source_file = self.file.take().ok_or_else(|| {
            FactStoreError::Io(std::io::Error::other(
                "prepared FactStore payload file was already consumed",
            ))
        })?;
        let payload_end = source_file.metadata()?.len();
        drop(source_file);

        let target_tmp = unique_tmp_path(target);
        match std::fs::rename(&source_path, &target_tmp) {
            Ok(()) => {}
            Err(rename_err) if rename_err.kind() == std::io::ErrorKind::CrossesDevices => {
                if let Err(copy_err) = std::fs::copy(&source_path, &target_tmp) {
                    let _ = std::fs::remove_file(&target_tmp);
                    let _ = std::fs::remove_file(&source_path);
                    return Err(copy_err.into());
                }
                if let Err(remove_err) = std::fs::remove_file(&source_path) {
                    let _ = std::fs::remove_file(&target_tmp);
                    return Err(remove_err.into());
                }
            }
            Err(err) => {
                let _ = std::fs::remove_file(&source_path);
                return Err(err.into());
            }
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&target_tmp);
        let mut file = match file {
            Ok(file) => file,
            Err(err) => {
                let _ = std::fs::remove_file(&target_tmp);
                return Err(err.into());
            }
        };
        if let Err(err) = file.seek(SeekFrom::Start(payload_end)) {
            drop(file);
            let _ = std::fs::remove_file(&target_tmp);
            return Err(err.into());
        }
        Ok((file, target_tmp, payload_end))
    }
}

impl Drop for PreparedFactStorePayload {
    fn drop(&mut self) {
        self.file.take();
        if let Some(path) = self.tmp_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl std::fmt::Debug for FactStoreWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactStoreWriter")
            .field("strings", &self.string_pool.lock().len())
            .field("queued", &self.sender.len())
            .finish()
    }
}

type StreamEncoder = Box<dyn FnOnce(&mut dyn Write) -> std::io::Result<()> + Send>;

/// Command shipped from worker → writer thread.
enum WriteCmd {
    /// Append one entry's payload to the streamed file and record an
    /// index row.
    Entry {
        key: u64,
        body_hash: u64,
        payload: Vec<u8>,
        /// Releases the payload's byte charge after the writer consumes (or
        /// drops) this command.
        _permit: BytePermit,
    },
    /// Encode one consumed compiler artifact directly into the payload
    /// section without first materializing an encoded `Vec<u8>`.
    StreamEntry {
        key: u64,
        body_hash: u64,
        encode: StreamEncoder,
        reply: Sender<std::io::Result<()>>,
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

struct ByteBudget {
    limit: usize,
    used: parking_lot::Mutex<usize>,
    available: parking_lot::Condvar,
}

impl ByteBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            used: parking_lot::Mutex::new(0),
            available: parking_lot::Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>, payload_bytes: usize) -> BytePermit {
        // A single payload larger than the budget is admitted exclusively;
        // otherwise it could never make progress. It still cannot coexist in
        // the queue with another charged payload.
        let charge = payload_bytes.max(1).min(self.limit);
        let mut used = self.used.lock();
        while used.saturating_add(charge) > self.limit {
            self.available.wait(&mut used);
        }
        *used += charge;
        BytePermit {
            budget: Arc::clone(self),
            charge,
        }
    }

    #[cfg(test)]
    fn try_acquire(self: &Arc<Self>, payload_bytes: usize) -> Option<BytePermit> {
        let charge = payload_bytes.max(1).min(self.limit);
        let mut used = self.used.lock();
        if used.saturating_add(charge) > self.limit {
            return None;
        }
        *used += charge;
        Some(BytePermit {
            budget: Arc::clone(self),
            charge,
        })
    }

    fn release(&self, charge: usize) {
        let mut used = self.used.lock();
        *used = used.saturating_sub(charge);
        self.available.notify_all();
    }
}

struct BytePermit {
    budget: Arc<ByteBudget>,
    charge: usize,
}

impl std::fmt::Debug for BytePermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytePermit")
            .field("charge", &self.charge)
            .finish()
    }
}

impl Drop for BytePermit {
    fn drop(&mut self) {
        self.budget.release(self.charge);
    }
}

struct PendingIndexEntry {
    key: u64,
    body_hash: u64,
    payload_offset: u64,
    payload_len: u32,
}

struct EntryWriter<'a> {
    inner: &'a mut BufWriter<File>,
    written: u64,
}

impl Write for EntryWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self.written.saturating_add(bytes.len() as u64);
        if next > u64::from(u32::MAX) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds 4 GiB",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl FactStoreWriter {
    /// Open a writer that streams payloads into a temp file next to
    /// `target` and atomically renames on [`Self::finish`]. Spawns a
    /// dedicated writer thread up front; the calling thread does no
    /// file I/O.
    pub fn create(target: &Path, table_id: u32, pipeline_hash: u64) -> FactStoreResult<Self> {
        let prepared = PreparedFactStorePayload::create_near(target)?;
        Self::create_from_prepared(target, table_id, pipeline_hash, prepared, Vec::new())
    }

    /// Adopt payload entries that a compiler already wrote into a prepared
    /// FactStore file, then accept ordinary/streamed entries and finalize the
    /// table atomically.
    ///
    /// Prepared bytes are not decoded, re-encoded, or copied through the
    /// process when the temporary and destination paths share a filesystem.
    /// The supplied index entries remain subject to the same bounds, duplicate
    /// key checks, and deterministic final sort as newly appended entries.
    pub fn create_from_prepared(
        target: &Path,
        table_id: u32,
        pipeline_hash: u64,
        prepared: PreparedFactStorePayload,
        entries: Vec<PreparedFactStoreEntry>,
    ) -> FactStoreResult<Self> {
        let prepared_len = prepared
            .file
            .as_ref()
            .ok_or_else(|| {
                FactStoreError::Io(std::io::Error::other(
                    "prepared FactStore payload was already consumed",
                ))
            })?
            .metadata()?
            .len();
        for entry in &entries {
            let payload_end = entry
                .payload_offset
                .checked_add(u64::from(entry.payload_len))
                .ok_or_else(|| {
                    FactStoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "prepared FactStore entry range overflow",
                    ))
                })?;
            if entry.payload_offset < HEADER_SIZE as u64 || payload_end > prepared_len {
                return Err(FactStoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "prepared FactStore entry range is outside the payload file",
                )));
            }
        }
        let (file, tmp_path, next_payload_offset) = prepared.relocate(target)?;
        let mut pending = Vec::with_capacity(entries.len());
        for entry in entries {
            pending.push(PendingIndexEntry {
                key: entry.key,
                body_hash: entry.body_hash,
                payload_offset: entry.payload_offset,
                payload_len: entry.payload_len,
            });
        }
        let target_path = target.to_path_buf();
        let (sender, receiver) = entry_channel();
        let byte_budget = Arc::new(ByteBudget::new(entry_queue_byte_budget()));
        let (finish_reply_tx, finish_reply_rx) = bounded::<FactStoreResult<usize>>(1);
        let cleanup_tmp_path = tmp_path.clone();
        let handle = std::thread::Builder::new()
            .name("factstore-writer".to_string())
            .spawn(move || {
                let outcome = run_writer_thread(
                    file,
                    receiver,
                    table_id,
                    pipeline_hash,
                    tmp_path,
                    target_path,
                    pending,
                    next_payload_offset,
                );
                if let Err(err) = outcome {
                    // The Finish path already replies through the
                    // one-shot. This branch covers a write error in
                    // an Entry command, where we never receive a
                    // Finish — surface the error via the reply
                    // channel anyway so `finish()` can return it.
                    let _ = finish_reply_tx.send(Err(err));
                }
            });
        let handle = match handle {
            Ok(handle) => handle,
            Err(err) => {
                let _ = std::fs::remove_file(cleanup_tmp_path);
                return Err(err.into());
            }
        };
        Ok(Self {
            string_pool: parking_lot::Mutex::new(StringPoolBuilder::new()),
            sender,
            byte_budget,
            stream_serial: parking_lot::Mutex::new(()),
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

    /// Append one borrowed entry to the writer.
    ///
    /// This compatibility API copies `payload` into an owned buffer,
    /// then delegates to [`Self::add_owned`]. Prefer `add_owned` when
    /// the caller already owns a serialized `Vec<u8>`.
    pub fn add(&self, key: u64, body_hash: u64, payload: &[u8]) -> FactStoreResult<()> {
        self.add_owned(key, body_hash, payload.to_vec())
    }

    /// Append one owned entry to the writer without cloning its payload.
    ///
    /// The payload moves into the writer thread through a small bounded
    /// channel. If that pipeline buffer is full, this call waits until
    /// the writer has consumed an earlier entry. Backpressure bounds
    /// queued payload memory; it does not cap, truncate, or drop facts.
    pub fn add_owned(&self, key: u64, body_hash: u64, payload: Vec<u8>) -> FactStoreResult<()> {
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
        let permit = self.byte_budget.acquire(payload.len());
        self.sender
            .send(WriteCmd::Entry {
                key,
                body_hash,
                payload,
                _permit: permit,
            })
            .map_err(|_| {
                FactStoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "factstore writer thread is no longer accepting entries",
                ))
            })
    }

    /// Serialize one owned artifact directly on the writer thread.
    ///
    /// The call waits until encoding and writing finish, so at most one
    /// streamed artifact is in flight and failures are reported at the exact
    /// entry boundary. This is the low-memory path for consumed compiler
    /// graphs whose encoded form may itself be gigabytes in aggregate.
    pub fn add_streamed<F>(&self, key: u64, body_hash: u64, encode: F) -> FactStoreResult<()>
    where
        F: FnOnce(&mut dyn Write) -> std::io::Result<()> + Send + 'static,
    {
        let _stream_guard = self.stream_serial.lock();
        let (reply_tx, reply_rx) = bounded(1);
        self.sender
            .send(WriteCmd::StreamEntry {
                key,
                body_hash,
                encode: Box::new(encode),
                reply: reply_tx,
            })
            .map_err(|_| {
                FactStoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "factstore writer thread is no longer accepting entries",
                ))
            })?;
        reply_rx.recv().map_err(|_| {
            FactStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "factstore writer exited during streamed entry",
            ))
        })??;
        Ok(())
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

        // Take the handle only after Finish was accepted. If the send
        // above fails, `Drop` still owns and joins the writer thread.
        let handle = self.writer_thread.lock().take().ok_or_else(|| {
            FactStoreError::Io(std::io::Error::other("factstore writer thread already joined"))
        })?;

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

/// Construct the bounded producer-to-writer entry channel. Kept in one
/// helper so tests can prove its capacity/backpressure contract without
/// scheduler timing assumptions.
fn entry_channel() -> (Sender<WriteCmd>, Receiver<WriteCmd>) {
    bounded(entry_queue_capacity())
}

/// Size the producer pipeline from the host's actual parallelism. This
/// remains bounded—so encoded payloads cannot accumulate with workspace
/// size—but gives every available producer a handoff slot instead of baking
/// one machine-specific queue length into the persistence layer.
fn entry_queue_capacity() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Maximum encoded payload bytes accepted by the producer queue. This is a
/// performance/backpressure budget, never an analysis limit: oversized facts
/// are admitted one at a time and written losslessly.
fn entry_queue_byte_budget() -> usize {
    const BYTES_PER_PRODUCER: usize = 4 * 1024 * 1024;
    std::env::var("BONSAI_FACTSTORE_QUEUE_BYTES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|budget| *budget > 0)
        .unwrap_or_else(|| entry_queue_capacity().saturating_mul(BYTES_PER_PRODUCER))
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
    mut entries: Vec<PendingIndexEntry>,
    mut next_payload_offset: u64,
) -> FactStoreResult<()> {
    let mut buf = BufWriter::new(file);

    loop {
        match receiver.recv() {
            Ok(WriteCmd::Entry {
                key,
                body_hash,
                payload,
                _permit,
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
            Ok(WriteCmd::StreamEntry {
                key,
                body_hash,
                encode,
                reply,
            }) => {
                let mut entry = EntryWriter {
                    inner: &mut buf,
                    written: 0,
                };
                if let Err(err) = encode(&mut entry) {
                    let _ = reply.send(Err(err));
                    drop(buf);
                    let _ = std::fs::remove_file(&tmp_path);
                    return Ok(());
                }
                let payload_len = u32::try_from(entry.written).map_err(|_| {
                    FactStoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "payload exceeds 4 GiB",
                    ))
                })?;
                entries.push(PendingIndexEntry {
                    key,
                    body_hash,
                    payload_offset: next_payload_offset,
                    payload_len,
                });
                next_payload_offset = next_payload_offset.saturating_add(entry.written);
                let _ = reply.send(Ok(()));
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
    if let Some(duplicate_key) = entries
        .windows(2)
        .find_map(|pair| (pair[0].key == pair[1].key).then_some(pair[0].key))
    {
        drop(buf);
        let _ = std::fs::remove_file(tmp_path);
        return Err(FactStoreError::DuplicateKey(duplicate_key));
    }

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
#[path = "writer_tests.rs"]
mod tests;
