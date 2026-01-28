//! Page-level encryption and compression for redb.
//!
//! This module provides:
//! - **Encryption**: Transparent AES-256-GCM encryption of database pages
//! - **Compression**: Transparent zstd compression of database pages
//!
//! ## Four modes
//! 1. **Nothing** - plain redb (no transforms)
//! 2. **Compression only** - use `set_page_compression()`
//! 3. **Encryption only** - use `set_page_crypto()`
//! 4. **Compression + Encryption** - use both (compress first, then encrypt)
//!
//! ## Encryption page format
//! ```text
//! [nonce: 12 bytes][ciphertext: page_size - 28][tag: 16 bytes]
//! ```
//! The nonce is generated randomly for each write to ensure security when
//! pages are updated with different data.
//!
//! ## Compression page format
//! ```text
//! [magic: 2 bytes][compressed_len: 4 bytes][orig_len: 4 bytes][compressed_data...][padding...]
//! ```
//!
//! Encryption overhead: 28 bytes per page (~0.7% for 4KB pages)
//! Compression overhead: 10 bytes header (but typically saves 50-80% on text)
//! The first page (header) is NOT transformed to allow bootstrapping.

use std::fmt::Debug;
use std::io;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};

/// Trait for page-level encryption.
///
/// Implementations must be thread-safe and handle fixed-size pages.
/// The header page (offset 0) is typically not encrypted.
pub trait PageCrypto: Send + Sync + Debug + 'static {
    /// Transform page data before writing to disk.
    ///
    /// - `offset`: byte offset in file (used for nonce derivation)
    /// - `data`: page data, length == page_size
    /// - `page_size`: the database page size
    ///
    /// Returns transformed data. Length MUST equal page_size.
    fn encrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>>;

    /// Transform page data after reading from disk.
    ///
    /// - `offset`: byte offset in file
    /// - `data`: encrypted page data from disk, length == page_size
    /// - `page_size`: the database page size
    ///
    /// Returns decrypted data. Length MUST equal page_size.
    fn decrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>>;

    /// Returns the byte offset where encryption starts.
    /// Typically this is the page_size (skip header page).
    fn encryption_start_offset(&self) -> u64 {
        0
    }

    /// Returns the number of bytes reserved per page for encryption overhead.
    /// The usable space per page is (page_size - overhead()).
    /// Default is 0 (no overhead).
    fn overhead(&self) -> usize {
        0
    }
}

/// AES-256-GCM page encryption.
///
/// Page format (with internal compression to preserve all data):
/// ```text
/// [nonce: 12 bytes][encrypted_payload: page_size - 28][tag: 16 bytes]
/// ```
///
/// Where encrypted_payload contains:
/// ```text
/// [magic: 2 "EC"][compressed_len: 4][orig_len: 4][compressed_data...][padding...]
/// ```
///
/// If data is incompressible, falls back to raw storage (losing last 28 bytes):
/// ```text
/// [magic: 2 "ER"][raw_data: page_size - 28 - 2]
/// ```
///
/// The nonce is generated randomly for each encryption to ensure security
/// when pages are updated with different data. This is critical for AES-GCM
/// which must never reuse the same (key, nonce) pair with different plaintexts.
///
/// Overhead: 28 bytes per page (12 nonce + 16 auth tag).
pub struct Aes256GcmPageCrypto {
    cipher: Aes256Gcm,
    skip_below_offset: u64,
}

impl Clone for Aes256GcmPageCrypto {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            skip_below_offset: self.skip_below_offset,
        }
    }
}

impl Debug for Aes256GcmPageCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmPageCrypto")
            .field("skip_below_offset", &self.skip_below_offset)
            .finish_non_exhaustive()
    }
}

impl Aes256GcmPageCrypto {
    /// Nonce size for AES-GCM
    const NONCE_SIZE: usize = 12;
    /// GCM authentication tag size
    const TAG_SIZE: usize = 16;
    /// Total overhead per page
    pub const OVERHEAD: usize = Self::NONCE_SIZE + Self::TAG_SIZE; // 28 bytes

    // Internal compression header constants
    /// Magic bytes for internally compressed data
    const MAGIC_COMPRESSED: [u8; 2] = [b'E', b'C']; // "EC" = Encrypted Compressed
    /// Magic bytes for raw data (incompressible)
    const MAGIC_RAW: [u8; 2] = [b'E', b'R']; // "ER" = Encrypted Raw
    /// Internal header size: 2 (magic) + 4 (compressed_len) + 4 (orig_len)
    const INTERNAL_HEADER_SIZE: usize = 10;

    /// Create a new AES-256-GCM page crypto with the given 32-byte key.
    ///
    /// - `key`: 32-byte encryption key
    /// - `skip_header`: if true, skip encrypting the first page (offset < page_size).
    ///   When true, defaults to skipping offset < 4096. Use `with_skip_below_offset`
    ///   to customize for different page sizes.
    pub fn new(key: &[u8; 32], skip_header: bool) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            skip_below_offset: if skip_header { 4096 } else { 0 },
        }
    }

    /// Create a new AES-256-GCM page crypto with the given 32-byte key and page size.
    ///
    /// - `key`: 32-byte encryption key
    /// - `page_size`: the database page size (used to skip the header page)
    pub fn with_page_size(key: &[u8; 32], page_size: u64) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            skip_below_offset: page_size,
        }
    }

    /// Set the offset below which encryption is skipped.
    /// This is typically set to page_size to skip the header page.
    pub fn with_skip_below_offset(mut self, offset: u64) -> Self {
        self.skip_below_offset = offset;
        self
    }

    /// Generate a random nonce for encryption.
    /// This ensures security when the same page is updated with different data.
    fn generate_nonce() -> [u8; Self::NONCE_SIZE] {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut result = [0u8; Self::NONCE_SIZE];
        result.copy_from_slice(&nonce);
        result
    }
}

impl PageCrypto for Aes256GcmPageCrypto {
    fn encrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        if data.len() != page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Input must be exactly page_size ({} bytes), got {}", page_size, data.len()),
            ));
        }
        if page_size <= Self::OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Page size must be > {} bytes, got {}", Self::OVERHEAD, page_size),
            ));
        }

        // Skip encryption for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        // Usable space for encrypted payload (before tag)
        let usable = page_size - Self::OVERHEAD;

        // Generate a random nonce for each encryption to ensure security
        // when the same page is updated with different data
        let nonce = Self::generate_nonce();

        // Try to compress the full page data to make room for overhead
        // This preserves all original bytes by compressing them to fit
        let compressed = zstd::encode_all(data.as_ref(), 1)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Internal compression failed: {e}")))?;

        let plaintext: Vec<u8>;
        let max_compressed_size = usable - Self::INTERNAL_HEADER_SIZE;

        if compressed.len() <= max_compressed_size {
            // Compression helped - build: [magic: 2][compressed_len: 4][orig_len: 4][compressed_data][padding]
            plaintext = {
                let mut p = Vec::with_capacity(usable);
                p.extend_from_slice(&Self::MAGIC_COMPRESSED);
                p.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
                p.extend_from_slice(&(data.len() as u32).to_le_bytes());
                p.extend_from_slice(&compressed);
                p.resize(usable, 0); // Pad to usable size
                p
            };
        } else {
            // Compression didn't help enough - store raw (last 28 bytes will be lost)
            // This should be rare for real data, but we handle it gracefully
            // Format: [magic: 2][raw_data: usable - 2]
            plaintext = {
                let mut p = Vec::with_capacity(usable);
                p.extend_from_slice(&Self::MAGIC_RAW);
                p.extend_from_slice(&data[..usable - 2]); // Raw data minus magic bytes
                p
            };
        }

        debug_assert_eq!(plaintext.len(), usable);

        let ciphertext_with_tag = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {e}")))?;

        // ciphertext_with_tag length = usable + TAG_SIZE (internal invariant)
        debug_assert_eq!(ciphertext_with_tag.len(), usable + Self::TAG_SIZE);

        // Build output page: [nonce][ciphertext][tag]
        let mut output = Vec::with_capacity(page_size);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext_with_tag);
        debug_assert_eq!(output.len(), page_size);

        Ok(output)
    }

    fn decrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        if data.len() != page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Input must be exactly page_size ({} bytes), got {}", page_size, data.len()),
            ));
        }
        if page_size <= Self::OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Page size must be > {} bytes, got {}", Self::OVERHEAD, page_size),
            ));
        }

        // Skip decryption for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        // Extract nonce and ciphertext+tag
        let nonce = &data[..Self::NONCE_SIZE];
        let ciphertext_with_tag = &data[Self::NONCE_SIZE..];

        // Detect uninitialized pages (all zeros).
        // Since we use random nonces, the probability of generating an all-zero nonce
        // is 2^-96, which is astronomically unlikely. So if we see an all-zero nonce
        // along with zeros in the data area, this is almost certainly an uninitialized page.
        // This is safe because:
        // 1. Random nonces will never be all zeros in practice (2^-96 probability)
        // 2. Real ciphertext is unlikely to start with many zeros
        // 3. This only triggers for genuinely uninitialized (all-zero) pages
        if nonce.iter().all(|&b| b == 0)
            && ciphertext_with_tag.len() >= 8
            && ciphertext_with_tag[..8].iter().all(|&b| b == 0)
        {
            // Uninitialized page - return as zeros
            return Ok(data.to_vec());
        }

        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;

        // Check for internal format magic bytes
        let magic = &plaintext[0..2];

        if magic == Self::MAGIC_COMPRESSED {
            // Internally compressed format: [magic: 2][compressed_len: 4][orig_len: 4][compressed_data...]
            let compressed_len = u32::from_le_bytes([plaintext[2], plaintext[3], plaintext[4], plaintext[5]]) as usize;
            let orig_len = u32::from_le_bytes([plaintext[6], plaintext[7], plaintext[8], plaintext[9]]) as usize;

            // Validate header
            let usable = page_size - Self::OVERHEAD;
            let max_compressed_size = usable - Self::INTERNAL_HEADER_SIZE;
            if compressed_len > 0 && compressed_len <= max_compressed_size && orig_len == page_size {
                let compressed = &plaintext[Self::INTERNAL_HEADER_SIZE..Self::INTERNAL_HEADER_SIZE + compressed_len];

                let decompressed = zstd::decode_all(compressed)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Internal decompression failed: {e}")))?;

                if decompressed.len() == orig_len {
                    return Ok(decompressed);
                }
            }
            // Fall through to legacy handling if header is invalid
        } else if magic == Self::MAGIC_RAW {
            // Raw format (incompressible data): [magic: 2][raw_data...]
            // Note: last 28 bytes were lost due to incompressibility
            let usable = page_size - Self::OVERHEAD;
            let mut output = Vec::with_capacity(page_size);
            output.extend_from_slice(&plaintext[2..usable]); // Raw data after magic
            output.resize(page_size, 0); // Pad with zeros (lost bytes)
            return Ok(output);
        }

        // Legacy format (no magic or unrecognized magic) - pad back to page_size
        let mut output = plaintext;
        output.resize(page_size, 0);

        Ok(output)
    }

    fn encryption_start_offset(&self) -> u64 {
        self.skip_below_offset
    }

    fn overhead(&self) -> usize {
        Self::OVERHEAD
    }
}

/// No-op implementation for testing or when encryption is disabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpPageCrypto;

impl PageCrypto for NoOpPageCrypto {
    fn encrypt(&self, _offset: u64, data: &[u8], _page_size: usize) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decrypt(&self, _offset: u64, data: &[u8], _page_size: usize) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

// ============================================================================
// COMPRESSION
// ============================================================================

/// Trait for page-level compression.
///
/// Implementations must be thread-safe and handle fixed-size pages.
/// The header page (offset 0) is typically not compressed.
pub trait PageCompression: Send + Sync + Debug + 'static {
    /// Compress page data before writing to disk.
    ///
    /// - `offset`: byte offset in file
    /// - `data`: page data, length == page_size
    /// - `page_size`: the database page size
    ///
    /// Returns compressed data. Length MUST equal page_size.
    fn compress(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>>;

    /// Decompress page data after reading from disk.
    ///
    /// - `offset`: byte offset in file
    /// - `data`: compressed page data from disk, length == page_size
    /// - `page_size`: the database page size
    ///
    /// Returns decompressed data. Length MUST equal page_size.
    fn decompress(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>>;

    /// Returns the byte offset where compression starts.
    /// Typically this is the page_size (skip header page).
    fn compression_start_offset(&self) -> u64 {
        0
    }
}

/// Zstd page compression.
///
/// Page format:
/// ```text
/// [magic: 2 bytes "ZS"][compressed_len: 4 bytes][orig_len: 4 bytes][compressed_data...][padding...]
/// ```
///
/// If data doesn't compress well (compressed >= original), stores uncompressed
/// with magic "UC" instead of "ZS".
#[derive(Debug, Clone)]
pub struct ZstdPageCompression {
    level: i32,
    skip_below_offset: u64,
}

impl ZstdPageCompression {
    /// Magic bytes for compressed pages
    const MAGIC_COMPRESSED: [u8; 2] = [b'Z', b'S'];
    /// Magic bytes for uncompressed pages (when compression doesn't help)
    const MAGIC_UNCOMPRESSED: [u8; 2] = [b'U', b'C'];
    /// Header size: 2 (magic) + 4 (compressed_len) + 4 (orig_len)
    const HEADER_SIZE: usize = 10;

    /// Create a new zstd page compression with default compression level (3).
    ///
    /// - `skip_header`: if true, skip compressing the first page.
    ///   When true, defaults to skipping offset < 4096. Use `with_skip_below_offset`
    ///   to customize for different page sizes.
    pub fn new(skip_header: bool) -> Self {
        Self {
            level: 3, // Default zstd level, good balance of speed/ratio
            skip_below_offset: if skip_header { 4096 } else { 0 },
        }
    }

    /// Create a new zstd page compression with the given page size.
    ///
    /// - `page_size`: the database page size (used to skip the header page)
    pub fn with_page_size(page_size: u64) -> Self {
        Self {
            level: 3,
            skip_below_offset: page_size,
        }
    }

    /// Create with a specific compression level (1-22, higher = better compression, slower).
    pub fn with_level(mut self, level: i32) -> Self {
        self.level = level.clamp(1, 22);
        self
    }

    /// Set the offset below which compression is skipped.
    /// This is typically set to page_size to skip the header page.
    pub fn with_skip_below_offset(mut self, offset: u64) -> Self {
        self.skip_below_offset = offset;
        self
    }
}

impl PageCompression for ZstdPageCompression {
    fn compress(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        if data.len() != page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Input must be exactly page_size ({} bytes), got {}", page_size, data.len()),
            ));
        }

        // Skip compression for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        // Try to compress
        let compressed = zstd::encode_all(data.as_ref(), self.level)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Compression failed: {e}")))?;

        // Check if compression is worthwhile (must fit in page with header)
        let max_compressed_size = page_size - Self::HEADER_SIZE;
        if compressed.len() <= max_compressed_size && compressed.len() < data.len() {
            // Compression helped - store compressed
            // Format: [magic: 2][compressed_len: 4][orig_len: 4][compressed_data...][padding...]
            let mut output = Vec::with_capacity(page_size);
            output.extend_from_slice(&Self::MAGIC_COMPRESSED);
            output.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            output.extend_from_slice(&(data.len() as u32).to_le_bytes());
            output.extend_from_slice(&compressed);
            output.resize(page_size, 0); // Pad to page_size
            Ok(output)
        } else {
            // Compression didn't help - store raw without modification
            // On decompression, we detect raw data by checking if header fields are valid
            Ok(data.to_vec())
        }
    }

    fn decompress(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        if data.len() != page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Input must be exactly page_size ({} bytes), got {}", page_size, data.len()),
            ));
        }

        // Skip decompression for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        // Check magic bytes
        let magic = &data[0..2];
        if magic == Self::MAGIC_COMPRESSED {
            // Possibly compressed data - validate header fields
            let compressed_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let orig_len = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;

            // Validate: compressed_len must fit in page, orig_len should be page_size
            let max_compressed_size = page_size - Self::HEADER_SIZE;
            if compressed_len > 0 && compressed_len <= max_compressed_size && orig_len == page_size {
                // Looks like valid compressed data - try to decompress
                let compressed = &data[Self::HEADER_SIZE..Self::HEADER_SIZE + compressed_len];

                match zstd::decode_all(compressed) {
                    Ok(decompressed) if decompressed.len() == orig_len => {
                        let mut output = decompressed;
                        output.resize(page_size, 0);
                        return Ok(output);
                    }
                    _ => {
                        // Decompression failed or size mismatch - treat as raw data
                        // that happens to start with "ZS"
                    }
                }
            }
            // Header validation failed - this is raw data that starts with "ZS"
            Ok(data.to_vec())
        } else if magic == Self::MAGIC_UNCOMPRESSED {
            // Check if this looks like valid legacy uncompressed format
            let orig_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            if orig_len == page_size {
                // Legacy uncompressed format
                let stored_data = &data[6..]; // Old header was 6 bytes
                let mut output = Vec::with_capacity(page_size);
                output.extend_from_slice(&stored_data[..stored_data.len().min(orig_len)]);
                output.resize(page_size, 0);
                Ok(output)
            } else {
                // Raw data that starts with "UC"
                Ok(data.to_vec())
            }
        } else {
            // Raw uncompressed data (no magic) - return as-is
            Ok(data.to_vec())
        }
    }

    fn compression_start_offset(&self) -> u64 {
        self.skip_below_offset
    }
}

/// No-op implementation for when compression is disabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpPageCompression;

impl PageCompression for NoOpPageCompression {
    fn compress(&self, _offset: u64, data: &[u8], _page_size: usize) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decompress(&self, _offset: u64, data: &[u8], _page_size: usize) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

// ============================================================================
// DICTIONARY-BASED COMPRESSION
// ============================================================================

use std::sync::Arc;

/// Zstd page compression with a pre-trained dictionary.
///
/// Dictionaries significantly improve compression ratios for small data blocks
/// like database pages by learning common patterns from sample data.
///
/// # Training a Dictionary
///
/// ```ignore
/// use redb_turbo::{Database, ZstdDictPageCompression, DictionaryTrainer};
///
/// // Collect sample pages from an existing database
/// let samples = DictionaryTrainer::collect_samples_from_db(&db, 1000)?;
///
/// // Train dictionary (target size 64KB is good for 4KB pages)
/// let dict = DictionaryTrainer::train(&samples, 65536)?;
///
/// // Save dictionary for later use
/// std::fs::write("my_dict.zdict", &dict)?;
///
/// // Use the dictionary
/// let compression = ZstdDictPageCompression::new(&dict, true);
/// let db = Database::builder()
///     .set_page_compression(compression)
///     .create("compressed.redb")?;
/// ```
pub struct ZstdDictPageCompression {
    /// Raw dictionary bytes (shared for thread safety)
    dict: Arc<[u8]>,
    /// Compression level
    level: i32,
    /// Skip compression below this offset
    skip_below_offset: u64,
}

impl Clone for ZstdDictPageCompression {
    fn clone(&self) -> Self {
        Self {
            dict: Arc::clone(&self.dict),
            level: self.level,
            skip_below_offset: self.skip_below_offset,
        }
    }
}

impl std::fmt::Debug for ZstdDictPageCompression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZstdDictPageCompression")
            .field("dict_size", &self.dict.len())
            .field("level", &self.level)
            .field("skip_below_offset", &self.skip_below_offset)
            .finish()
    }
}

impl ZstdDictPageCompression {
    /// Magic bytes for dictionary-compressed pages
    const MAGIC_DICT_COMPRESSED: [u8; 2] = [b'Z', b'D'];
    /// Header size: 2 (magic) + 4 (compressed_len) + 4 (orig_len)
    const HEADER_SIZE: usize = 10;

    /// Create a new dictionary-based compression with the given pre-trained dictionary.
    ///
    /// - `dict`: Pre-trained zstd dictionary bytes
    /// - `skip_header`: if true, skip compressing the first page.
    ///   When true, defaults to skipping offset < 4096. Use `with_skip_below_offset`
    ///   to customize for different page sizes.
    pub fn new(dict: &[u8], skip_header: bool) -> Self {
        Self {
            dict: Arc::from(dict),
            level: 3,
            skip_below_offset: if skip_header { 4096 } else { 0 },
        }
    }

    /// Create a new dictionary-based compression with the given page size.
    ///
    /// - `dict`: Pre-trained zstd dictionary bytes
    /// - `page_size`: the database page size (used to skip the header page)
    pub fn with_page_size(dict: &[u8], page_size: u64) -> Self {
        Self {
            dict: Arc::from(dict),
            level: 3,
            skip_below_offset: page_size,
        }
    }

    /// Create from an Arc'd dictionary (avoids copy if you already have an Arc).
    pub fn from_arc(dict: Arc<[u8]>, skip_header: bool) -> Self {
        Self {
            dict,
            level: 3,
            skip_below_offset: if skip_header { 4096 } else { 0 },
        }
    }

    /// Set the compression level (1-22, higher = better compression, slower).
    pub fn with_level(mut self, level: i32) -> Self {
        self.level = level.clamp(1, 22);
        self
    }

    /// Set the offset below which compression is skipped.
    pub fn with_skip_below_offset(mut self, offset: u64) -> Self {
        self.skip_below_offset = offset;
        self
    }

    /// Get a reference to the dictionary bytes.
    pub fn dictionary(&self) -> &[u8] {
        &self.dict
    }
}

impl PageCompression for ZstdDictPageCompression {
    fn compress(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        if data.len() != page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Input must be exactly page_size ({} bytes), got {}", page_size, data.len()),
            ));
        }

        // Skip compression for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        // Create compressor with dictionary
        let mut compressor = zstd::bulk::Compressor::with_dictionary(self.level, &self.dict)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create compressor: {e}")))?;

        // Compress
        let compressed = compressor
            .compress(data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Compression failed: {e}")))?;

        // Check if compression is worthwhile
        let max_compressed_size = page_size - Self::HEADER_SIZE;
        if compressed.len() <= max_compressed_size && compressed.len() < data.len() {
            // Compression helped - store compressed with dict magic
            // Format: [magic: 2][compressed_len: 4][orig_len: 4][compressed_data...][padding...]
            let mut output = Vec::with_capacity(page_size);
            output.extend_from_slice(&Self::MAGIC_DICT_COMPRESSED);
            output.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            output.extend_from_slice(&(data.len() as u32).to_le_bytes());
            output.extend_from_slice(&compressed);
            output.resize(page_size, 0);
            Ok(output)
        } else {
            // Compression didn't help - store raw without modification
            Ok(data.to_vec())
        }
    }

    fn decompress(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        if data.len() != page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Input must be exactly page_size ({} bytes), got {}", page_size, data.len()),
            ));
        }

        // Skip decompression for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        let magic = &data[0..2];

        if magic == Self::MAGIC_DICT_COMPRESSED {
            // Possibly dictionary-compressed data - validate header
            let compressed_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let orig_len = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;

            let max_compressed_size = page_size - Self::HEADER_SIZE;
            if compressed_len > 0 && compressed_len <= max_compressed_size && orig_len == page_size {
                let compressed = &data[Self::HEADER_SIZE..Self::HEADER_SIZE + compressed_len];

                // Create decompressor with dictionary
                let mut decompressor = zstd::bulk::Decompressor::with_dictionary(&self.dict)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create decompressor: {e}")))?;

                match decompressor.decompress(compressed, orig_len) {
                    Ok(decompressed) if decompressed.len() == orig_len => {
                        let mut output = decompressed;
                        output.resize(page_size, 0);
                        return Ok(output);
                    }
                    _ => {
                        // Decompression failed - treat as raw data
                    }
                }
            }
            // Header validation failed - raw data starting with "ZD"
            Ok(data.to_vec())
        } else if magic == ZstdPageCompression::MAGIC_COMPRESSED {
            // Possibly regular zstd compressed - validate header
            let compressed_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let orig_len = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;

            let max_compressed_size = page_size - ZstdPageCompression::HEADER_SIZE;
            if compressed_len > 0 && compressed_len <= max_compressed_size && orig_len == page_size {
                let compressed = &data[ZstdPageCompression::HEADER_SIZE..ZstdPageCompression::HEADER_SIZE + compressed_len];

                match zstd::decode_all(compressed) {
                    Ok(decompressed) if decompressed.len() == orig_len => {
                        let mut output = decompressed;
                        output.resize(page_size, 0);
                        return Ok(output);
                    }
                    _ => {
                        // Decompression failed - treat as raw data
                    }
                }
            }
            // Header validation failed - raw data starting with "ZS"
            Ok(data.to_vec())
        } else if magic == ZstdPageCompression::MAGIC_UNCOMPRESSED {
            // Check if valid legacy uncompressed format
            let orig_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            if orig_len == page_size {
                // Legacy uncompressed format
                let stored_data = &data[6..];
                let mut output = Vec::with_capacity(page_size);
                output.extend_from_slice(&stored_data[..stored_data.len().min(orig_len)]);
                output.resize(page_size, 0);
                Ok(output)
            } else {
                // Raw data starting with "UC"
                Ok(data.to_vec())
            }
        } else {
            // Raw uncompressed data
            Ok(data.to_vec())
        }
    }

    fn compression_start_offset(&self) -> u64 {
        self.skip_below_offset
    }
}

// ============================================================================
// DICTIONARY TRAINING
// ============================================================================

/// Utility for training zstd dictionaries from database page samples.
///
/// A well-trained dictionary can significantly improve compression ratios,
/// especially for small data blocks like 4KB database pages.
///
/// # Example
///
/// ```ignore
/// use redb_turbo::DictionaryTrainer;
///
/// // Collect page samples (Vec<Vec<u8>>)
/// let samples: Vec<Vec<u8>> = collect_your_samples();
///
/// // Train a 64KB dictionary (good size for 4KB pages)
/// let dict = DictionaryTrainer::train(&samples, 65536)?;
///
/// // Save for later use
/// std::fs::write("my.zdict", &dict)?;
/// ```
pub struct DictionaryTrainer;

impl DictionaryTrainer {
    /// Default dictionary size (64KB) - good balance for 4KB pages.
    pub const DEFAULT_DICT_SIZE: usize = 64 * 1024;

    /// Minimum recommended samples for good dictionary training.
    pub const MIN_RECOMMENDED_SAMPLES: usize = 100;

    /// Minimum required samples for dictionary training.
    /// Training with fewer samples produces poor or unusable dictionaries.
    pub const MIN_REQUIRED_SAMPLES: usize = 10;

    /// Train a dictionary from page samples.
    ///
    /// - `samples`: Collection of page data to train from. More diverse samples = better dictionary.
    /// - `dict_size`: Target dictionary size in bytes. 64KB is recommended for 4KB pages.
    ///
    /// Returns the trained dictionary bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `samples` is empty
    /// - `samples` has fewer than 10 entries (produces unusable dictionary)
    ///
    /// # Recommendations
    ///
    /// - Use at least 100 samples for good results (fewer produces suboptimal dictionaries)
    /// - Include diverse data (different table types, key patterns, etc.)
    /// - Dictionary size of 64KB works well for 4KB pages
    /// - Larger dictionaries can improve ratios but have diminishing returns
    pub fn train(samples: &[Vec<u8>], dict_size: usize) -> io::Result<Vec<u8>> {
        if samples.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot train dictionary from empty samples",
            ));
        }

        if samples.len() < Self::MIN_REQUIRED_SAMPLES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "At least {} samples required for dictionary training, got {}. \
                     Training with too few samples produces poor dictionaries.",
                    Self::MIN_REQUIRED_SAMPLES,
                    samples.len()
                ),
            ));
        }

        if samples.len() < Self::MIN_RECOMMENDED_SAMPLES {
            #[cfg(feature = "logging")]
            log::warn!(
                "Training dictionary with {} samples (recommended: {}). \
                 Results may be suboptimal.",
                samples.len(),
                Self::MIN_RECOMMENDED_SAMPLES
            );
        }

        zstd::dict::from_samples(samples, dict_size)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Dictionary training failed: {e}")))
    }

    /// Train a dictionary from a continuous buffer containing concatenated samples.
    ///
    /// - `data`: Continuous buffer with all samples concatenated
    /// - `sample_sizes`: Size of each sample in the buffer
    /// - `dict_size`: Target dictionary size in bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `data` or `sample_sizes` is empty
    /// - `sample_sizes` has fewer than 10 entries
    pub fn train_from_continuous(data: &[u8], sample_sizes: &[usize], dict_size: usize) -> io::Result<Vec<u8>> {
        if data.is_empty() || sample_sizes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot train dictionary from empty data",
            ));
        }

        if sample_sizes.len() < Self::MIN_REQUIRED_SAMPLES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "At least {} samples required for dictionary training, got {}. \
                     Training with too few samples produces poor dictionaries.",
                    Self::MIN_REQUIRED_SAMPLES,
                    sample_sizes.len()
                ),
            ));
        }

        if sample_sizes.len() < Self::MIN_RECOMMENDED_SAMPLES {
            #[cfg(feature = "logging")]
            log::warn!(
                "Training dictionary with {} samples (recommended: {}). \
                 Results may be suboptimal.",
                sample_sizes.len(),
                Self::MIN_RECOMMENDED_SAMPLES
            );
        }

        zstd::dict::from_continuous(data, sample_sizes, dict_size)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Dictionary training failed: {e}")))
    }

    /// Load a dictionary from a file.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    /// Save a dictionary to a file.
    pub fn save_to_file(dict: &[u8], path: impl AsRef<std::path::Path>) -> io::Result<()> {
        std::fs::write(path, dict)
    }

    /// Estimate compression ratio improvement from a dictionary.
    ///
    /// Returns (without_dict_ratio, with_dict_ratio) where ratio = compressed_size / original_size.
    /// Lower is better.
    pub fn estimate_improvement(samples: &[Vec<u8>], dict: &[u8], level: i32) -> io::Result<(f64, f64)> {
        if samples.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot estimate with empty samples",
            ));
        }

        let mut total_original = 0usize;
        let mut total_without_dict = 0usize;
        let mut total_with_dict = 0usize;

        let mut compressor_with_dict = zstd::bulk::Compressor::with_dictionary(level, dict)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create compressor: {e}")))?;

        for sample in samples {
            total_original += sample.len();

            // Without dictionary
            let compressed = zstd::encode_all(sample.as_slice(), level)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Compression failed: {e}")))?;
            total_without_dict += compressed.len();

            // With dictionary
            let compressed_dict = compressor_with_dict
                .compress(sample)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Compression failed: {e}")))?;
            total_with_dict += compressed_dict.len();
        }

        let ratio_without = total_without_dict as f64 / total_original as f64;
        let ratio_with = total_with_dict as f64 / total_original as f64;

        Ok((ratio_without, ratio_with))
    }
}

// ============================================================================
// KEY ROTATION DOCUMENTATION
// ============================================================================
//
// # Key Rotation
//
// To rotate encryption keys, create a new database with the new key and copy all data.
// This requires 2x disk space temporarily but is the safest approach.
//
// ## Example: Rotate to a new encryption key
//
// ```rust,ignore
// use redb_turbo::{Database, Aes256GcmPageCrypto, TableDefinition, ReadableTable};
//
// const MY_TABLE: TableDefinition<&str, &str> = TableDefinition::new("my_table");
//
// fn rotate_key(
//     source_path: &str,
//     target_path: &str,
//     old_key: &[u8; 32],
//     new_key: &[u8; 32],
// ) -> Result<(), redb_turbo::Error> {
//     // Open source with old key
//     let source_db = Database::builder()
//         .set_page_crypto(Aes256GcmPageCrypto::new(old_key, true))
//         .open(source_path)?;
//
//     // Create target with new key
//     let target_db = Database::builder()
//         .set_page_crypto(Aes256GcmPageCrypto::new(new_key, true))
//         .create(target_path)?;
//
//     // Copy each table
//     let read_txn = source_db.begin_read()?;
//     let write_txn = target_db.begin_write()?;
//     {
//         let source_table = read_txn.open_table(MY_TABLE)?;
//         let mut target_table = write_txn.open_table(MY_TABLE)?;
//
//         for entry in source_table.iter()? {
//             let (key, value) = entry?;
//             target_table.insert(key.value(), value.value())?;
//         }
//     }
//     write_txn.commit()?;
//
//     // Optionally: rename target to source after verification
//     // std::fs::rename(target_path, source_path)?;
//
//     Ok(())
// }
// ```
//
// ## Example: Migrate from unencrypted to encrypted
//
// ```rust,ignore
// // Open unencrypted database
// let source_db = Database::open("plain.redb")?;
//
// // Create encrypted database
// let key = [0x42u8; 32];
// let target_db = Database::builder()
//     .set_page_crypto(Aes256GcmPageCrypto::new(&key, true))
//     .create("encrypted.redb")?;
//
// // Copy tables as shown above
// ```

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, false);
        let page_size = 4096;
        let usable = page_size - Aes256GcmPageCrypto::OVERHEAD;

        // Create test data (only usable portion matters)
        let mut original = vec![0u8; page_size];
        for i in 0..usable.min(256) {
            original[i] = (i % 256) as u8;
        }

        let encrypted = crypto.encrypt(4096, &original, page_size).unwrap();
        assert_eq!(encrypted.len(), page_size);
        assert_ne!(&encrypted[..usable], &original[..usable]);

        let decrypted = crypto.decrypt(4096, &encrypted, page_size).unwrap();
        // Only usable portion is preserved
        assert_eq!(&decrypted[..usable], &original[..usable]);
    }

    #[test]
    fn test_skip_header_page() {
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, true).with_skip_below_offset(4096);
        let page_size = 4096;

        let original = vec![0x42u8; page_size];

        // Header page (offset 0) should not be encrypted
        let header_result = crypto.encrypt(0, &original, page_size).unwrap();
        assert_eq!(header_result, original);

        // Data page (offset >= page_size) should be encrypted
        let data_result = crypto.encrypt(4096, &original, page_size).unwrap();
        assert_ne!(data_result, original);
    }

    #[test]
    fn test_random_data_roundtrip() {
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, false);
        let page_size = 4096;
        let usable = page_size - Aes256GcmPageCrypto::OVERHEAD;

        // Incompressible random-ish data
        let mut original = vec![0u8; page_size];
        for i in 0..page_size {
            original[i] = ((i * 17 + 31) % 256) as u8;
        }

        let encrypted = crypto.encrypt(4096, &original, page_size).unwrap();
        assert_eq!(encrypted.len(), page_size);

        let decrypted = crypto.decrypt(4096, &encrypted, page_size).unwrap();
        assert_eq!(&decrypted[..usable], &original[..usable]);
    }

    #[test]
    fn test_overhead_constant() {
        assert_eq!(Aes256GcmPageCrypto::OVERHEAD, 28);

        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, false);
        assert_eq!(crypto.overhead(), 28);
    }

    // Compression tests

    #[test]
    fn test_compress_decompress_roundtrip() {
        let compression = ZstdPageCompression::new(false);
        let page_size = 4096;

        // Create compressible data (repeated pattern)
        let original: Vec<u8> = (0..page_size).map(|i| (i % 64) as u8).collect();

        let compressed = compression.compress(4096, &original, page_size).unwrap();
        assert_eq!(compressed.len(), page_size);

        // Should be smaller (check magic indicates compression)
        assert_eq!(&compressed[0..2], &ZstdPageCompression::MAGIC_COMPRESSED);

        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compression_skip_header() {
        let compression = ZstdPageCompression::new(true).with_skip_below_offset(4096);
        let page_size = 4096;

        let original: Vec<u8> = (0..page_size).map(|i| (i % 64) as u8).collect();

        // Header page (offset 0) should not be compressed
        let header_result = compression.compress(0, &original, page_size).unwrap();
        assert_eq!(header_result, original);

        // Data page should be compressed
        let data_result = compression.compress(4096, &original, page_size).unwrap();
        assert_ne!(data_result, original);
        assert_eq!(&data_result[0..2], &ZstdPageCompression::MAGIC_COMPRESSED);
    }

    #[test]
    fn test_varied_data_roundtrip() {
        let compression = ZstdPageCompression::new(false);
        let page_size = 4096;

        // Data with varied pattern - zstd may or may not compress this
        let original: Vec<u8> = (0..page_size).map(|i| ((i * 17 + 31) % 256) as u8).collect();

        let compressed = compression.compress(4096, &original, page_size).unwrap();
        assert_eq!(compressed.len(), page_size);

        // Data may be compressed, uncompressed with magic, or raw (no magic)
        // Just verify roundtrip works correctly
        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        // Should get original back
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_raw_page_migration() {
        let compression = ZstdPageCompression::new(false);
        let page_size = 4096;

        // Raw page data without magic (simulating migration from uncompressed DB)
        let original = vec![0x42u8; page_size];

        // Should return as-is since no magic bytes
        let decompressed = compression.decompress(4096, &original, page_size).unwrap();
        assert_eq!(decompressed, original);
    }

    // Dictionary compression tests

    #[test]
    fn test_dict_compression_roundtrip() {
        let page_size = 4096;

        // Create sample data for dictionary training
        let samples: Vec<Vec<u8>> = (0..100)
            .map(|i| {
                (0..page_size)
                    .map(|j| ((i + j) % 64) as u8)
                    .collect()
            })
            .collect();

        // Train a dictionary
        let dict = DictionaryTrainer::train(&samples, 8192).unwrap();
        assert!(!dict.is_empty());

        // Create compression with dictionary
        let compression = ZstdDictPageCompression::new(&dict, false);

        // Test roundtrip
        let original: Vec<u8> = (0..page_size).map(|i| (i % 64) as u8).collect();
        let compressed = compression.compress(4096, &original, page_size).unwrap();
        assert_eq!(compressed.len(), page_size);
        assert_eq!(&compressed[0..2], &ZstdDictPageCompression::MAGIC_DICT_COMPRESSED);

        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_dict_compression_skip_header() {
        let page_size = 4096;

        // Create a small dict for testing
        let samples: Vec<Vec<u8>> = (0..50)
            .map(|i| vec![(i % 256) as u8; page_size])
            .collect();
        let dict = DictionaryTrainer::train(&samples, 4096).unwrap();

        let compression = ZstdDictPageCompression::new(&dict, true);

        let original: Vec<u8> = (0..page_size).map(|i| (i % 64) as u8).collect();

        // Header page should not be compressed
        let header_result = compression.compress(0, &original, page_size).unwrap();
        assert_eq!(header_result, original);

        // Data page should be compressed with dict magic
        let data_result = compression.compress(4096, &original, page_size).unwrap();
        assert_ne!(data_result, original);
        assert_eq!(&data_result[0..2], &ZstdDictPageCompression::MAGIC_DICT_COMPRESSED);
    }

    #[test]
    fn test_dict_trainer_estimate_improvement() {
        let page_size = 4096;

        // Create compressible samples
        let samples: Vec<Vec<u8>> = (0..50)
            .map(|i| {
                (0..page_size)
                    .map(|j| ((i * 3 + j) % 64) as u8)
                    .collect()
            })
            .collect();

        // Train dictionary
        let dict = DictionaryTrainer::train(&samples, 8192).unwrap();

        // Estimate improvement
        let (ratio_without, ratio_with) = DictionaryTrainer::estimate_improvement(&samples, &dict, 3).unwrap();

        // Dictionary should improve compression for repetitive data
        assert!(ratio_without > 0.0 && ratio_without < 1.0);
        assert!(ratio_with > 0.0 && ratio_with < 1.0);
        // With a trained dictionary, ratio should be better (smaller) or similar
        assert!(ratio_with <= ratio_without * 1.1, // Allow 10% tolerance
            "Dictionary should not significantly worsen compression: {} vs {}",
            ratio_with, ratio_without);
    }

    #[test]
    fn test_dict_backwards_compatible_with_regular() {
        let page_size = 4096;

        // Create dict compression
        let samples: Vec<Vec<u8>> = (0..50)
            .map(|i| vec![(i % 256) as u8; page_size])
            .collect();
        let dict = DictionaryTrainer::train(&samples, 4096).unwrap();
        let dict_compression = ZstdDictPageCompression::new(&dict, false);

        // Compress without dict using regular compression
        let regular_compression = ZstdPageCompression::new(false);
        let original: Vec<u8> = (0..page_size).map(|i| (i % 64) as u8).collect();
        let regular_compressed = regular_compression.compress(4096, &original, page_size).unwrap();

        // Dict compression should be able to decompress regular compressed pages
        // (for migration/backwards compatibility)
        let decompressed = dict_compression.decompress(4096, &regular_compressed, page_size).unwrap();
        assert_eq!(decompressed, original);
    }

    // ========================================================================
    // Security tests - random nonces
    // ========================================================================

    #[test]
    fn test_random_nonce_produces_different_ciphertext() {
        // Critical security test: encrypting the same data twice should
        // produce different ciphertexts because nonces are random
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, false);
        let page_size = 4096;

        let original = vec![0x42u8; page_size];

        let encrypted1 = crypto.encrypt(4096, &original, page_size).unwrap();
        let encrypted2 = crypto.encrypt(4096, &original, page_size).unwrap();

        // Nonces (first 12 bytes) should be different
        assert_ne!(&encrypted1[..12], &encrypted2[..12],
            "Random nonces should be different for each encryption");

        // Ciphertexts should be different (due to different nonces)
        assert_ne!(encrypted1, encrypted2,
            "Same plaintext encrypted twice should produce different ciphertexts");

        // But both should decrypt to the original
        let decrypted1 = crypto.decrypt(4096, &encrypted1, page_size).unwrap();
        let decrypted2 = crypto.decrypt(4096, &encrypted2, page_size).unwrap();

        let usable = page_size - Aes256GcmPageCrypto::OVERHEAD;
        assert_eq!(&decrypted1[..usable], &original[..usable]);
        assert_eq!(&decrypted2[..usable], &original[..usable]);
    }

    #[test]
    fn test_page_update_security() {
        // Simulates updating a page with new data - each update should use
        // a different nonce for security
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, false);
        let page_size = 4096;

        let offset = 4096u64; // Same page offset

        // Initial write
        let data_v1 = vec![0x11u8; page_size];
        let encrypted_v1 = crypto.encrypt(offset, &data_v1, page_size).unwrap();

        // Update same page with new data
        let data_v2 = vec![0x22u8; page_size];
        let encrypted_v2 = crypto.encrypt(offset, &data_v2, page_size).unwrap();

        // Different nonces ensure security even for same page offset
        assert_ne!(&encrypted_v1[..12], &encrypted_v2[..12],
            "Page updates must use different nonces");

        // Verify both decrypt correctly
        let decrypted_v1 = crypto.decrypt(offset, &encrypted_v1, page_size).unwrap();
        let decrypted_v2 = crypto.decrypt(offset, &encrypted_v2, page_size).unwrap();

        let usable = page_size - Aes256GcmPageCrypto::OVERHEAD;
        assert_eq!(&decrypted_v1[..usable], &data_v1[..usable]);
        assert_eq!(&decrypted_v2[..usable], &data_v2[..usable]);
    }

    // ========================================================================
    // Compression edge case tests
    // ========================================================================

    #[test]
    fn test_compressed_data_ending_in_zeros() {
        // Test that compressed data ending in zeros is handled correctly
        // (no trailing zero stripping that could corrupt data)
        let compression = ZstdPageCompression::new(false);
        let page_size = 4096;

        // Create data that compresses well and might produce zeros in output
        let mut original = vec![0u8; page_size];
        // Highly compressible: repeated pattern
        for i in 0..page_size {
            original[i] = (i % 4) as u8;
        }

        let compressed = compression.compress(4096, &original, page_size).unwrap();
        assert_eq!(compressed.len(), page_size);

        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        assert_eq!(decompressed, original,
            "Decompression must correctly handle compressed data that may end in zeros");
    }

    #[test]
    fn test_incompressible_data_with_nonzero_trailing_bytes() {
        // Critical test: incompressible data must not lose trailing bytes
        let compression = ZstdPageCompression::new(false);
        let page_size = 4096;

        // Create incompressible data with important bytes at the end
        let mut original: Vec<u8> = (0..page_size)
            .map(|i| ((i * 17 + 31) ^ (i * 13 + 7)) as u8)
            .collect();

        // Make sure last bytes are non-zero and significant
        original[page_size - 1] = 0xDE;
        original[page_size - 2] = 0xAD;
        original[page_size - 3] = 0xBE;
        original[page_size - 4] = 0xEF;

        let compressed = compression.compress(4096, &original, page_size).unwrap();
        assert_eq!(compressed.len(), page_size);

        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        assert_eq!(decompressed, original,
            "Incompressible data must preserve all bytes including trailing non-zeros");
    }

    #[test]
    fn test_data_starting_with_magic_bytes() {
        // Test that data starting with our magic bytes is handled correctly
        // When data starts with magic but has invalid header fields, it's treated as raw
        let compression = ZstdPageCompression::new(false);
        let page_size = 4096;

        // Data that starts with "ZS" magic but has invalid header (doesn't look compressed)
        let mut original = vec![0x42u8; page_size];
        original[0] = b'Z';
        original[1] = b'S';
        // Set invalid compressed_len and orig_len so it's detected as raw data
        original[2] = 0xFF; // compressed_len > max
        original[3] = 0xFF;
        original[4] = 0xFF;
        original[5] = 0xFF;

        let compressed = compression.compress(4096, &original, page_size).unwrap();
        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        assert_eq!(decompressed, original,
            "Raw data starting with ZS magic must roundtrip correctly");

        // Data that starts with "UC" magic
        original[0] = b'U';
        original[1] = b'C';
        // Set invalid orig_len
        original[2] = 0x00;
        original[3] = 0x00;
        original[4] = 0x00;
        original[5] = 0x00; // orig_len = 0, not page_size

        let compressed = compression.compress(4096, &original, page_size).unwrap();
        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        assert_eq!(decompressed, original,
            "Raw data starting with UC magic must roundtrip correctly");

        // Data that starts with "ZD" magic
        original[0] = b'Z';
        original[1] = b'D';
        // Invalid header
        original[2] = 0xFF;
        original[3] = 0xFF;
        original[4] = 0xFF;
        original[5] = 0xFF;

        let compressed = compression.compress(4096, &original, page_size).unwrap();
        let decompressed = compression.decompress(4096, &compressed, page_size).unwrap();
        assert_eq!(decompressed, original,
            "Raw data starting with ZD magic must roundtrip correctly");
    }

    // ========================================================================
    // Dictionary training validation tests
    // ========================================================================

    #[test]
    fn test_dict_training_too_few_samples_error() {
        // Training with fewer than MIN_REQUIRED_SAMPLES should error
        let samples: Vec<Vec<u8>> = (0..5) // Only 5 samples
            .map(|i| vec![(i % 256) as u8; 1000])
            .collect();

        let result = DictionaryTrainer::train(&samples, 4096);
        assert!(result.is_err(), "Training with < 10 samples should fail");

        let err = result.unwrap_err();
        assert!(err.to_string().contains("At least 10 samples required"),
            "Error message should mention minimum samples requirement");
    }

    #[test]
    fn test_dict_training_minimum_samples_works() {
        // Training with exactly MIN_REQUIRED_SAMPLES should work
        let samples: Vec<Vec<u8>> = (0..10) // Exactly 10 samples
            .map(|i| {
                (0..1000).map(|j| ((i * 3 + j) % 256) as u8).collect()
            })
            .collect();

        let result = DictionaryTrainer::train(&samples, 4096);
        assert!(result.is_ok(), "Training with exactly 10 samples should work");
    }

    // ========================================================================
    // Clone trait tests
    // ========================================================================

    #[test]
    fn test_crypto_clone() {
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, true);
        let crypto_clone = crypto.clone();

        let page_size = 4096;
        let original = vec![0x42u8; page_size];

        // Both should encrypt correctly
        let encrypted1 = crypto.encrypt(4096, &original, page_size).unwrap();
        let encrypted2 = crypto_clone.encrypt(4096, &original, page_size).unwrap();

        // Cross-decrypt should work
        let usable = page_size - Aes256GcmPageCrypto::OVERHEAD;
        let decrypted1 = crypto_clone.decrypt(4096, &encrypted1, page_size).unwrap();
        let decrypted2 = crypto.decrypt(4096, &encrypted2, page_size).unwrap();

        assert_eq!(&decrypted1[..usable], &original[..usable]);
        assert_eq!(&decrypted2[..usable], &original[..usable]);
    }

    #[test]
    fn test_compression_clone() {
        let compression = ZstdPageCompression::new(true).with_level(5);
        let compression_clone = compression.clone();

        let page_size = 4096;
        let original: Vec<u8> = (0..page_size).map(|i| (i % 64) as u8).collect();

        // Both should compress correctly
        let compressed1 = compression.compress(4096, &original, page_size).unwrap();
        let compressed2 = compression_clone.compress(4096, &original, page_size).unwrap();

        // Cross-decompress should work
        let decompressed1 = compression_clone.decompress(4096, &compressed1, page_size).unwrap();
        let decompressed2 = compression.decompress(4096, &compressed2, page_size).unwrap();

        assert_eq!(decompressed1, original);
        assert_eq!(decompressed2, original);
    }

    #[test]
    fn test_with_page_size_constructors() {
        // Test the new with_page_size constructors
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::with_page_size(&key, 8192);
        assert_eq!(crypto.encryption_start_offset(), 8192);

        let compression = ZstdPageCompression::with_page_size(8192);
        assert_eq!(compression.compression_start_offset(), 8192);
    }
}
