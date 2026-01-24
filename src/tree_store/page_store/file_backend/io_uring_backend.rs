//! io_uring-based file backend for Linux with automatic fallback.
//!
//! This module provides a `FileBackend` that attempts to use io_uring for
//! batched I/O operations. If io_uring is unavailable (old kernel, no permissions),
//! it falls back to the standard pread/pwrite-based backend.

use crate::{DatabaseError, Result, StorageBackend};
use std::cell::UnsafeCell;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

use super::unix::FileBackend as StandardFileBackend;

const RING_SIZE: u32 = 256;

/// Linux file backend with io_uring support and automatic fallback.
#[derive(Debug)]
pub struct FileBackend {
    inner: FileBackendInner,
}

#[derive(Debug)]
enum FileBackendInner {
    Standard(StandardFileBackend),
    IoUring(IoUringFileBackend),
}

impl FileBackend {
    /// Creates a new backend which stores data to the given file.
    /// Attempts to use io_uring if available, falls back to standard pread/pwrite.
    pub fn new(file: File) -> Result<Self, DatabaseError> {
        // Check environment variable to force disable io_uring for benchmarking
        if std::env::var("REDB_DISABLE_IOURING").is_ok() {
            return Ok(Self {
                inner: FileBackendInner::Standard(StandardFileBackend::new(file)?),
            });
        }

        // Try to create io_uring ring
        match io_uring::IoUring::new(RING_SIZE) {
            Ok(ring) => {
                // io_uring available, use it
                match IoUringFileBackend::new(file, ring) {
                    Ok(backend) => Ok(Self {
                        inner: FileBackendInner::IoUring(backend),
                    }),
                    Err(e) => Err(e),
                }
            }
            Err(_) => {
                // io_uring not available, fall back to standard
                Ok(Self {
                    inner: FileBackendInner::Standard(StandardFileBackend::new(file)?),
                })
            }
        }
    }
}

impl StorageBackend for FileBackend {
    fn len(&self) -> std::result::Result<u64, io::Error> {
        match &self.inner {
            FileBackendInner::Standard(b) => b.len(),
            FileBackendInner::IoUring(b) => b.len(),
        }
    }

    fn read(&self, offset: u64, len: usize) -> std::result::Result<Vec<u8>, io::Error> {
        match &self.inner {
            FileBackendInner::Standard(b) => b.read(offset, len),
            FileBackendInner::IoUring(b) => b.read(offset, len),
        }
    }

    fn set_len(&self, len: u64) -> std::result::Result<(), io::Error> {
        match &self.inner {
            FileBackendInner::Standard(b) => b.set_len(len),
            FileBackendInner::IoUring(b) => b.set_len(len),
        }
    }

    fn sync_data(&self, eventual: bool) -> std::result::Result<(), io::Error> {
        match &self.inner {
            FileBackendInner::Standard(b) => b.sync_data(eventual),
            FileBackendInner::IoUring(b) => b.sync_data(eventual),
        }
    }

    fn write(&self, offset: u64, data: &[u8]) -> std::result::Result<(), io::Error> {
        match &self.inner {
            FileBackendInner::Standard(b) => b.write(offset, data),
            FileBackendInner::IoUring(b) => b.write(offset, data),
        }
    }

    fn write_batch(&self, ops: &[(u64, &[u8])]) -> std::result::Result<(), io::Error> {
        match &self.inner {
            FileBackendInner::Standard(b) => b.write_batch(ops),
            FileBackendInner::IoUring(b) => b.write_batch(ops),
        }
    }
}

/// io_uring-based file backend implementation.
///
/// Uses UnsafeCell for the ring because IoUring is not Sync, but we guarantee
/// single-threaded access within the database's locking model.
struct IoUringFileBackend {
    file: File,
    // UnsafeCell because IoUring is not Sync, but FileBackend requires Sync.
    // Safety: The ring is only accessed through &self methods which are synchronized
    // at a higher level by the database's transaction locking.
    ring: UnsafeCell<io_uring::IoUring>,
}

impl std::fmt::Debug for IoUringFileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoUringFileBackend")
            .field("file", &self.file)
            .field("ring", &"<io_uring::IoUring>")
            .finish()
    }
}

// Safety: IoUringFileBackend is Sync because the ring is only accessed through
// synchronized methods. The database ensures single-writer semantics.
unsafe impl Sync for IoUringFileBackend {}
unsafe impl Send for IoUringFileBackend {}

impl IoUringFileBackend {
    fn new(file: File, ring: io_uring::IoUring) -> Result<Self, DatabaseError> {
        // Acquire file lock (same as standard backend)
        let fd = file.as_raw_fd();
        let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Err(DatabaseError::DatabaseAlreadyOpen);
            } else {
                return Err(err.into());
            }
        }

        Ok(Self {
            file,
            ring: UnsafeCell::new(ring),
        })
    }

    /// Get mutable reference to the ring.
    /// Safety: Caller must ensure exclusive access (guaranteed by database locking).
    #[inline]
    fn ring_mut(&self) -> &mut io_uring::IoUring {
        unsafe { &mut *self.ring.get() }
    }

    /// Drain completion queue entries, checking for errors.
    fn drain_completions(&self, count: usize) -> std::result::Result<(), io::Error> {
        let ring = self.ring_mut();
        let mut completed = 0;

        while completed < count {
            if let Some(cqe) = ring.completion().next() {
                let result = cqe.result();
                if result < 0 {
                    return Err(io::Error::from_raw_os_error(-result));
                }
                completed += 1;
            } else {
                // Should not happen if submit_and_wait worked correctly
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "io_uring completion queue unexpectedly empty",
                ));
            }
        }

        Ok(())
    }
}

impl StorageBackend for IoUringFileBackend {
    fn len(&self) -> std::result::Result<u64, io::Error> {
        Ok(self.file.metadata()?.len())
    }

    fn read(&self, offset: u64, len: usize) -> std::result::Result<Vec<u8>, io::Error> {
        // For single reads, use standard pread (io_uring overhead not worth it)
        use std::os::unix::fs::FileExt;
        let mut buffer = vec![0; len];
        self.file.read_exact_at(&mut buffer, offset)?;
        Ok(buffer)
    }

    fn set_len(&self, len: u64) -> std::result::Result<(), io::Error> {
        self.file.set_len(len)
    }

    fn sync_data(&self, _eventual: bool) -> std::result::Result<(), io::Error> {
        // Note: Could use io_uring FSYNC opcode here, but sync_data is called
        // infrequently (once per commit), so the overhead savings are minimal.
        self.file.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> std::result::Result<(), io::Error> {
        // For single writes, use standard pwrite (io_uring overhead not worth it)
        use std::os::unix::fs::FileExt;
        self.file.write_all_at(data, offset)
    }

    fn write_batch(&self, ops: &[(u64, &[u8])]) -> std::result::Result<(), io::Error> {
        if ops.is_empty() {
            return Ok(());
        }

        // For small batches, sequential writes may be faster due to io_uring setup overhead
        if ops.len() < 4 {
            for (offset, data) in ops {
                self.write(*offset, data)?;
            }
            return Ok(());
        }

        let ring = self.ring_mut();
        let fd = io_uring::types::Fd(self.file.as_raw_fd());

        let mut submitted = 0;
        let batch_size = RING_SIZE as usize;

        for (offset, data) in ops {
            let write_op = io_uring::opcode::Write::new(fd, data.as_ptr(), data.len() as u32)
                .offset(*offset)
                .build()
                .user_data(submitted as u64);

            // Safety: The write operation references data that lives for the duration of this call.
            // We wait for all completions before returning.
            unsafe {
                if ring.submission().push(&write_op).is_err() {
                    // Submission queue full, submit and wait for completions
                    ring.submit_and_wait(submitted % batch_size)?;
                    self.drain_completions(submitted % batch_size)?;
                    submitted = 0;

                    // Retry push
                    ring.submission()
                        .push(&write_op)
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "io_uring SQ full"))?;
                }
            }
            submitted += 1;

            // Submit in batches to avoid SQ overflow
            if submitted % batch_size == 0 && submitted > 0 {
                ring.submit_and_wait(batch_size)?;
                self.drain_completions(batch_size)?;
            }
        }

        // Submit and wait for remaining operations
        let remaining = submitted % batch_size;
        if remaining > 0 || submitted == batch_size {
            let to_wait = if remaining == 0 && submitted > 0 {
                batch_size
            } else {
                remaining
            };
            if to_wait > 0 {
                ring.submit_and_wait(to_wait)?;
                self.drain_completions(to_wait)?;
            }
        }

        Ok(())
    }
}

impl Drop for IoUringFileBackend {
    fn drop(&mut self) {
        // Release file lock
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    #[test]
    fn test_io_uring_backend_basic() {
        let tmpfile = NamedTempFile::new().unwrap();
        let file = tmpfile.reopen().unwrap();

        let backend = FileBackend::new(file).unwrap();

        // Write some data
        let data = b"Hello, io_uring!";
        backend.write(0, data).unwrap();
        backend.sync_data(false).unwrap();

        // Read it back
        let read_data = backend.read(0, data.len()).unwrap();
        assert_eq!(&read_data, data);
    }

    #[test]
    fn test_io_uring_backend_batch_write() {
        let tmpfile = NamedTempFile::new().unwrap();
        let file = tmpfile.reopen().unwrap();

        let backend = FileBackend::new(file).unwrap();

        // Prepare batch writes (simulating page writes)
        let page_size = 4096;
        let pages: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![i as u8; page_size])
            .collect();

        let ops: Vec<(u64, &[u8])> = pages
            .iter()
            .enumerate()
            .map(|(i, data)| ((i * page_size) as u64, data.as_slice()))
            .collect();

        // Batch write
        backend.write_batch(&ops).unwrap();
        backend.sync_data(false).unwrap();

        // Verify each page
        for (i, expected) in pages.iter().enumerate() {
            let read_data = backend.read((i * page_size) as u64, page_size).unwrap();
            assert_eq!(&read_data, expected, "Page {} mismatch", i);
        }
    }

    #[test]
    fn test_io_uring_backend_set_len() {
        let tmpfile = NamedTempFile::new().unwrap();
        let file = tmpfile.reopen().unwrap();

        let backend = FileBackend::new(file).unwrap();

        backend.set_len(1024 * 1024).unwrap();
        assert_eq!(backend.len().unwrap(), 1024 * 1024);

        backend.set_len(0).unwrap();
        assert_eq!(backend.len().unwrap(), 0);
    }
}
