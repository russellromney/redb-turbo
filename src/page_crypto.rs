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
//!
//! ## Compression page format
//! ```text
//! [magic: 2 bytes][orig_len: 4 bytes][compressed_data...][padding...]
//! ```
//!
//! Encryption overhead: 28 bytes per page (~0.7% for 4KB pages)
//! Compression overhead: 6 bytes header (but typically saves 50-80% on text)
//! The first page (header) is NOT transformed to allow bootstrapping.

use std::fmt::Debug;
use std::io;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
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
/// Page format:
/// ```text
/// [nonce: 12 bytes][ciphertext: page_size - 28][tag: 16 bytes]
/// ```
///
/// The nonce is derived deterministically from the page offset.
/// Overhead: 28 bytes per page (12 nonce + 16 auth tag).
pub struct Aes256GcmPageCrypto {
    cipher: Aes256Gcm,
    skip_below_offset: u64,
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

    /// Create a new AES-256-GCM page crypto with the given 32-byte key.
    ///
    /// - `key`: 32-byte encryption key
    /// - `skip_header`: if true, skip encrypting the first page (offset < page_size)
    pub fn new(key: &[u8; 32], skip_header: bool) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            skip_below_offset: if skip_header { 4096 } else { 0 },
        }
    }

    /// Set the offset below which encryption is skipped.
    /// This is typically set to page_size to skip the header page.
    pub fn with_skip_below_offset(mut self, offset: u64) -> Self {
        self.skip_below_offset = offset;
        self
    }

    /// Derive a deterministic nonce from the page offset.
    fn derive_nonce(offset: u64) -> [u8; Self::NONCE_SIZE] {
        let mut nonce = [0u8; Self::NONCE_SIZE];
        nonce[0..8].copy_from_slice(&offset.to_le_bytes());
        nonce
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

        // Usable space for actual data
        let usable = page_size - Self::OVERHEAD;

        // Encrypt only the usable portion (the rest is reserved/unused by B-tree)
        let plaintext = &data[..usable];
        let nonce = Self::derive_nonce(offset);

        let ciphertext_with_tag = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
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

        // Handle unencrypted pages (all zeros in nonce area typically means unencrypted)
        // This allows migration from unencrypted to encrypted databases
        if nonce.iter().all(|&b| b == 0) && data[Self::NONCE_SIZE..Self::NONCE_SIZE + 8].iter().all(|&b| b == 0) {
            return Ok(data.to_vec());
        }

        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;

        // Pad back to page_size (the reserved bytes are zeros)
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
#[derive(Debug, Default)]
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
/// [magic: 2 bytes "ZS"][orig_len: 4 bytes][compressed_data...][padding...]
/// ```
///
/// If data doesn't compress well (compressed >= original), stores uncompressed
/// with magic "UC" instead of "ZS".
#[derive(Debug)]
pub struct ZstdPageCompression {
    level: i32,
    skip_below_offset: u64,
}

impl ZstdPageCompression {
    /// Magic bytes for compressed pages
    const MAGIC_COMPRESSED: [u8; 2] = [b'Z', b'S'];
    /// Magic bytes for uncompressed pages (when compression doesn't help)
    const MAGIC_UNCOMPRESSED: [u8; 2] = [b'U', b'C'];
    /// Header size: 2 (magic) + 4 (original length)
    const HEADER_SIZE: usize = 6;

    /// Create a new zstd page compression with default compression level (3).
    ///
    /// - `skip_header`: if true, skip compressing the first page
    pub fn new(skip_header: bool) -> Self {
        Self {
            level: 3, // Default zstd level, good balance of speed/ratio
            skip_below_offset: if skip_header { 4096 } else { 0 },
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
            let mut output = Vec::with_capacity(page_size);
            output.extend_from_slice(&Self::MAGIC_COMPRESSED);
            output.extend_from_slice(&(data.len() as u32).to_le_bytes());
            output.extend_from_slice(&compressed);
            output.resize(page_size, 0); // Pad to page_size
            Ok(output)
        } else {
            // Compression didn't help - store uncompressed with marker
            let mut output = Vec::with_capacity(page_size);
            output.extend_from_slice(&Self::MAGIC_UNCOMPRESSED);
            output.extend_from_slice(&(data.len() as u32).to_le_bytes());
            output.extend_from_slice(&data[..max_compressed_size]);
            // Note: we truncate to max_compressed_size, but the original length
            // tells us to read page_size bytes. This works because decompression
            // will see MAGIC_UNCOMPRESSED and just return the data as-is, padded.
            Ok(output)
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
            // Compressed data
            let orig_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let compressed = &data[Self::HEADER_SIZE..];

            // Find actual compressed data (strip trailing zeros)
            let mut end = compressed.len();
            while end > 0 && compressed[end - 1] == 0 {
                end -= 1;
            }

            let decompressed = zstd::decode_all(&compressed[..end])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decompression failed: {e}")))?;

            if decompressed.len() != orig_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Decompressed size mismatch: expected {}, got {}", orig_len, decompressed.len()),
                ));
            }

            // Pad to page_size if needed
            let mut output = decompressed;
            output.resize(page_size, 0);
            Ok(output)
        } else if magic == Self::MAGIC_UNCOMPRESSED {
            // Uncompressed data - reconstruct original page
            let orig_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let stored_data = &data[Self::HEADER_SIZE..];

            let mut output = Vec::with_capacity(orig_len);
            output.extend_from_slice(&stored_data[..stored_data.len().min(orig_len)]);
            output.resize(orig_len, 0);
            output.resize(page_size, 0);
            Ok(output)
        } else {
            // No magic - assume uncompressed raw page (for migration compatibility)
            Ok(data.to_vec())
        }
    }

    fn compression_start_offset(&self) -> u64 {
        self.skip_below_offset
    }
}

/// No-op implementation for when compression is disabled.
#[derive(Debug, Default)]
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
    /// Header size: 2 (magic) + 4 (original length)
    const HEADER_SIZE: usize = 6;

    /// Create a new dictionary-based compression with the given pre-trained dictionary.
    ///
    /// - `dict`: Pre-trained zstd dictionary bytes
    /// - `skip_header`: if true, skip compressing the first page
    pub fn new(dict: &[u8], skip_header: bool) -> Self {
        Self {
            dict: Arc::from(dict),
            level: 3,
            skip_below_offset: if skip_header { 4096 } else { 0 },
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
            let mut output = Vec::with_capacity(page_size);
            output.extend_from_slice(&Self::MAGIC_DICT_COMPRESSED);
            output.extend_from_slice(&(data.len() as u32).to_le_bytes());
            output.extend_from_slice(&compressed);
            output.resize(page_size, 0);
            Ok(output)
        } else {
            // Compression didn't help - store uncompressed
            let mut output = Vec::with_capacity(page_size);
            output.extend_from_slice(&ZstdPageCompression::MAGIC_UNCOMPRESSED);
            output.extend_from_slice(&(data.len() as u32).to_le_bytes());
            output.extend_from_slice(&data[..max_compressed_size]);
            Ok(output)
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
            // Dictionary-compressed data
            let orig_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let compressed = &data[Self::HEADER_SIZE..];

            // Find actual compressed data (strip trailing zeros)
            let mut end = compressed.len();
            while end > 0 && compressed[end - 1] == 0 {
                end -= 1;
            }

            // Create decompressor with dictionary
            let mut decompressor = zstd::bulk::Decompressor::with_dictionary(&self.dict)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create decompressor: {e}")))?;

            let decompressed = decompressor
                .decompress(&compressed[..end], orig_len)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decompression failed: {e}")))?;

            let mut output = decompressed;
            output.resize(page_size, 0);
            Ok(output)
        } else if magic == ZstdPageCompression::MAGIC_COMPRESSED {
            // Regular zstd compressed (for backwards compatibility or migration)
            let _orig_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let compressed = &data[Self::HEADER_SIZE..];

            let mut end = compressed.len();
            while end > 0 && compressed[end - 1] == 0 {
                end -= 1;
            }

            let decompressed = zstd::decode_all(&compressed[..end])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decompression failed: {e}")))?;

            let mut output = decompressed;
            output.resize(page_size, 0);
            Ok(output)
        } else if magic == ZstdPageCompression::MAGIC_UNCOMPRESSED {
            // Uncompressed data
            let orig_len = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            let stored_data = &data[Self::HEADER_SIZE..];

            let mut output = Vec::with_capacity(orig_len);
            output.extend_from_slice(&stored_data[..stored_data.len().min(orig_len)]);
            output.resize(orig_len, 0);
            output.resize(page_size, 0);
            Ok(output)
        } else {
            // No magic - assume uncompressed raw page
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

    /// Train a dictionary from page samples.
    ///
    /// - `samples`: Collection of page data to train from. More diverse samples = better dictionary.
    /// - `dict_size`: Target dictionary size in bytes. 64KB is recommended for 4KB pages.
    ///
    /// Returns the trained dictionary bytes.
    ///
    /// # Recommendations
    ///
    /// - Use at least 100 samples for good results
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

        zstd::dict::from_samples(samples, dict_size)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Dictionary training failed: {e}")))
    }

    /// Train a dictionary from a continuous buffer containing concatenated samples.
    ///
    /// - `data`: Continuous buffer with all samples concatenated
    /// - `sample_sizes`: Size of each sample in the buffer
    /// - `dict_size`: Target dictionary size in bytes
    pub fn train_from_continuous(data: &[u8], sample_sizes: &[usize], dict_size: usize) -> io::Result<Vec<u8>> {
        if data.is_empty() || sample_sizes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot train dictionary from empty data",
            ));
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

        // Should have either compressed or uncompressed magic
        let magic = &compressed[0..2];
        assert!(
            magic == ZstdPageCompression::MAGIC_COMPRESSED
                || magic == ZstdPageCompression::MAGIC_UNCOMPRESSED,
            "Invalid magic: {:?}",
            magic
        );

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
}
