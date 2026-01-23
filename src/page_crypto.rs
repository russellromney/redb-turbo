//! Page-level encryption and compression for redb.
//!
//! This module provides transparent encryption and compression of database pages.
//! Order of operations:
//! - Write: compress -> encrypt -> disk
//! - Read: disk -> decrypt -> decompress
//!
//! Supports optional zstd dictionary for improved compression ratios.
//! The first page (header) is NOT encrypted to allow bootstrapping.

use std::fmt::Debug;
use std::io;
use std::sync::Arc;

#[cfg(feature = "encryption")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

#[cfg(feature = "encryption")]
use zstd::dict::{DecoderDictionary, EncoderDictionary};

/// Trait for page-level encryption and compression.
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
    /// Returns decrypted/decompressed data. Length MUST equal page_size.
    fn decrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>>;

    /// Returns the byte offset where encryption starts.
    /// Typically this is the page_size (skip header page).
    fn encryption_start_offset(&self) -> u64 {
        0 // Subclasses can override to skip header
    }
}

/// Page header for encrypted/compressed pages.
/// Stored at the beginning of each encrypted page.
#[cfg(feature = "encryption")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PageHeader {
    /// Ciphertext length (including GCM tag)
    ciphertext_len: u32,
    /// Flags: bit 0 = compressed
    flags: u8,
    /// Reserved for future use
    _reserved: [u8; 3],
    /// AES-GCM nonce (12 bytes)
    nonce: [u8; 12],
}

#[cfg(feature = "encryption")]
impl PageHeader {
    const SIZE: usize = 20; // 4 + 1 + 3 + 12

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        bytes[4] = self.flags;
        // bytes[5..8] reserved
        bytes[8..20].copy_from_slice(&self.nonce);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut ciphertext_len_bytes = [0u8; 4];
        ciphertext_len_bytes.copy_from_slice(&bytes[0..4]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[8..20]);

        Self {
            ciphertext_len: u32::from_le_bytes(ciphertext_len_bytes),
            flags: bytes[4],
            _reserved: [0; 3],
            nonce,
        }
    }

    fn is_compressed(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

/// AES-256-GCM encryption with optional zstd compression.
///
/// Page format:
/// ```text
/// [PageHeader: 20 bytes][Encrypted data][Padding to page_size]
/// ```
///
/// The encrypted data contains:
/// - If compressed: zstd compressed original data + 16-byte GCM tag
/// - If not compressed: original data + 16-byte GCM tag
///
/// Supports pre-trained zstd dictionaries for improved compression ratios.
#[cfg(feature = "encryption")]
pub struct Aes256GcmPageCrypto {
    cipher: Aes256Gcm,
    compress: bool,
    compression_level: i32,
    /// Skip encryption for offsets below this value (header pages)
    skip_below_offset: u64,
    /// Pre-trained zstd compression dictionary (optional)
    encoder_dict: Option<Arc<EncoderDictionary<'static>>>,
    /// Pre-trained zstd decompression dictionary (optional)
    decoder_dict: Option<Arc<DecoderDictionary<'static>>>,
}

#[cfg(feature = "encryption")]
impl Debug for Aes256GcmPageCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmPageCrypto")
            .field("compress", &self.compress)
            .field("compression_level", &self.compression_level)
            .field("skip_below_offset", &self.skip_below_offset)
            .field("has_dictionary", &self.encoder_dict.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "encryption")]
impl Aes256GcmPageCrypto {
    /// GCM authentication tag size
    const TAG_SIZE: usize = 16;

    /// Create a new AES-256-GCM page crypto with the given 32-byte key.
    ///
    /// - `key`: 32-byte encryption key
    /// - `compress`: enable zstd compression before encryption
    /// - `skip_header`: if true, skip encrypting the first page (offset < page_size)
    pub fn new(key: &[u8; 32], compress: bool, skip_header: bool) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            compress,
            compression_level: 3, // zstd default
            skip_below_offset: if skip_header { u64::MAX } else { 0 }, // Set properly later
            encoder_dict: None,
            decoder_dict: None,
        }
    }

    /// Create with custom compression level (1-22, default 3).
    pub fn with_compression_level(mut self, level: i32) -> Self {
        self.compression_level = level.clamp(1, 22);
        self
    }

    /// Set the offset below which encryption is skipped.
    /// This is typically set to page_size to skip the header page.
    pub fn with_skip_below_offset(mut self, offset: u64) -> Self {
        self.skip_below_offset = offset;
        self
    }

    /// Set a pre-trained zstd dictionary for improved compression.
    ///
    /// The dictionary should be trained on representative database pages.
    /// Use `train_dictionary()` to create one from sample pages.
    pub fn with_dictionary(mut self, dict_data: &[u8]) -> Self {
        // Create encoder dictionary at the configured compression level
        let encoder_dict = EncoderDictionary::copy(dict_data, self.compression_level);
        self.encoder_dict = Some(Arc::new(encoder_dict));

        // Create decoder dictionary
        let decoder_dict = DecoderDictionary::copy(dict_data);
        self.decoder_dict = Some(Arc::new(decoder_dict));

        self
    }

    /// Train a zstd dictionary from sample pages.
    ///
    /// - `samples`: Collection of raw page data to train on
    /// - `dict_size`: Target dictionary size in bytes (recommended: 16KB-112KB)
    ///
    /// Returns the trained dictionary bytes which can be saved to a file
    /// and later loaded with `with_dictionary()`.
    pub fn train_dictionary(samples: &[Vec<u8>], dict_size: usize) -> io::Result<Vec<u8>> {
        // Collect all samples as references
        let sample_refs: Vec<&[u8]> = samples.iter().map(|s| s.as_slice()).collect();

        zstd::dict::from_samples(&sample_refs, dict_size)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Dictionary training failed: {}", e)))
    }

    /// Derive a deterministic nonce from the page offset.
    /// Uses the offset as the primary component for reproducibility.
    fn derive_nonce(&self, offset: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&offset.to_le_bytes());
        // Remaining 4 bytes are zero (could add version/counter if needed)
        nonce
    }
}

#[cfg(feature = "encryption")]
impl PageCrypto for Aes256GcmPageCrypto {
    fn encrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        assert_eq!(data.len(), page_size, "Input must be exactly page_size");

        // Skip encryption for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        // Available space for ciphertext (after header)
        let available = page_size - PageHeader::SIZE;

        // Step 1: Always try to compress first (needed to fit data + GCM tag)
        // Use dictionary if available for better compression
        let compressed_data = if let Some(ref dict) = self.encoder_dict {
            let mut output = Vec::new();
            let mut encoder = zstd::stream::Encoder::with_prepared_dictionary(&mut output, dict.as_ref())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            io::copy(&mut io::Cursor::new(data), &mut encoder)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            encoder.finish()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            output
        } else {
            zstd::encode_all(data.as_ref(), self.compression_level)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        };

        // Determine what to encrypt: use compressed if it fits, otherwise we have a problem
        let (payload, is_compressed) = if compressed_data.len() + Self::TAG_SIZE <= available {
            // Compression worked - use compressed data
            (compressed_data, true)
        } else if page_size + Self::TAG_SIZE <= available {
            // Rare case: compression made it bigger but uncompressed fits
            // This shouldn't happen with typical page sizes but handle it
            (data.to_vec(), false)
        } else {
            // Page data won't fit - this means page_size is too small
            // With 4096 byte pages: available = 4076, max payload = 4060
            // Uncompressed 4096 bytes won't fit. Compression MUST reduce size.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Page data cannot be encrypted: compressed size {} + tag {} > available {}. \
                     Page data must be compressible or use larger page size.",
                    compressed_data.len(),
                    Self::TAG_SIZE,
                    available
                ),
            ));
        };

        // Step 2: Encrypt with AES-256-GCM
        let nonce = self.derive_nonce(offset);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {e}")))?;

        // Step 3: Build output page
        let header = PageHeader {
            ciphertext_len: ciphertext.len() as u32,
            flags: if is_compressed { 0x01 } else { 0x00 },
            _reserved: [0; 3],
            nonce,
        };

        let mut output = Vec::with_capacity(page_size);
        output.extend_from_slice(&header.to_bytes());
        output.extend_from_slice(&ciphertext);
        // Pad to page_size with zeros
        output.resize(page_size, 0);

        Ok(output)
    }

    fn decrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        assert_eq!(data.len(), page_size, "Input must be exactly page_size");

        // Skip decryption for header pages
        if offset < self.skip_below_offset {
            return Ok(data.to_vec());
        }

        // Parse header
        let header = PageHeader::from_bytes(&data[..PageHeader::SIZE]);

        // Validate ciphertext length
        let ciphertext_len = header.ciphertext_len as usize;

        // Handle unencrypted/empty pages (ciphertext_len=0 means not encrypted)
        // This can happen during database initialization or for newly allocated pages
        if ciphertext_len == 0 {
            // Page was never encrypted - return as-is
            // This allows mixed encrypted/unencrypted databases during migration
            return Ok(data.to_vec());
        }

        if PageHeader::SIZE + ciphertext_len > page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid page header: ciphertext_len={} exceeds available space (header_size={}, page_size={})",
                    ciphertext_len,
                    PageHeader::SIZE,
                    page_size
                ),
            ));
        }

        let ciphertext = &data[PageHeader::SIZE..PageHeader::SIZE + ciphertext_len];

        // Decrypt
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&header.nonce), ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;

        // Decompress if needed (use dictionary if available)
        let result = if header.is_compressed() {
            if let Some(ref dict) = self.decoder_dict {
                let mut output = Vec::new();
                let mut decoder = zstd::stream::Decoder::with_prepared_dictionary(
                    io::Cursor::new(&plaintext),
                    dict.as_ref()
                ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                io::copy(&mut decoder, &mut output)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                output
            } else {
                zstd::decode_all(plaintext.as_slice())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            }
        } else {
            plaintext
        };

        // Verify size
        if result.len() != page_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Decrypted page size mismatch: {} != {}",
                    result.len(),
                    page_size
                ),
            ));
        }

        Ok(result)
    }

    fn encryption_start_offset(&self) -> u64 {
        self.skip_below_offset
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

#[cfg(all(test, feature = "encryption"))]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        // Note: compression is always attempted internally now
        let crypto = Aes256GcmPageCrypto::new(&key, true, false);
        let page_size = 4096;

        // Use compressible data (typical for database pages with some zeros/structure)
        let mut original = vec![0u8; page_size];
        for i in 0..100 {
            original[i] = (i % 256) as u8;
        }

        let encrypted = crypto.encrypt(4096, &original, page_size).unwrap();
        assert_eq!(encrypted.len(), page_size);
        assert_ne!(encrypted, original);

        let decrypted = crypto.decrypt(4096, &encrypted, page_size).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_compress_encrypt_roundtrip() {
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, true, false);
        let page_size = 4096;

        // Highly compressible data
        let original = vec![0u8; page_size];

        let encrypted = crypto.encrypt(4096, &original, page_size).unwrap();
        assert_eq!(encrypted.len(), page_size);

        let decrypted = crypto.decrypt(4096, &encrypted, page_size).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_skip_header_page() {
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, true, true).with_skip_below_offset(4096);
        let page_size = 4096;

        // Use compressible data
        let original = vec![0u8; page_size];

        // Header page (offset 0) should not be encrypted
        let header_result = crypto.encrypt(0, &original, page_size).unwrap();
        assert_eq!(header_result, original);

        // Data page (offset >= page_size) should be encrypted
        let data_result = crypto.encrypt(4096, &original, page_size).unwrap();
        assert_ne!(data_result, original);
    }

    #[test]
    fn test_varied_data_roundtrip() {
        let key = [0x42u8; 32];
        let crypto = Aes256GcmPageCrypto::new(&key, true, false);
        let page_size = 4096;

        // Data with some structure (like a B+tree page would have)
        let mut original = vec![0u8; page_size];
        // Header-like area
        original[0..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // Some key-value pairs
        for i in 0..50 {
            let offset = 64 + i * 64;
            original[offset..offset + 8].copy_from_slice(&(i as u64).to_le_bytes());
        }

        let encrypted = crypto.encrypt(4096, &original, page_size).unwrap();
        assert_eq!(encrypted.len(), page_size);

        let decrypted = crypto.decrypt(4096, &encrypted, page_size).unwrap();
        assert_eq!(decrypted, original);
    }
}
