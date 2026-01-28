//! Page-level encryption for redb.
//!
//! This module provides transparent AES-256-GCM encryption of database pages.
//! Each encrypted page reserves space for the nonce and authentication tag.
//!
//! Page format:
//! ```text
//! [nonce: 12 bytes][ciphertext: page_size - 28][tag: 16 bytes]
//! ```
//!
//! Overhead: 28 bytes per page (~0.7% for 4KB pages)
//! The first page (header) is NOT encrypted to allow bootstrapping.

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
            skip_below_offset: if skip_header { u64::MAX } else { 0 },
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
        assert_eq!(data.len(), page_size, "Input must be exactly page_size");
        assert!(page_size > Self::OVERHEAD, "Page size must be > {} bytes", Self::OVERHEAD);

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

        // ciphertext_with_tag length = usable + TAG_SIZE
        assert_eq!(ciphertext_with_tag.len(), usable + Self::TAG_SIZE);

        // Build output page: [nonce][ciphertext][tag]
        let mut output = Vec::with_capacity(page_size);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext_with_tag);
        assert_eq!(output.len(), page_size);

        Ok(output)
    }

    fn decrypt(&self, offset: u64, data: &[u8], page_size: usize) -> io::Result<Vec<u8>> {
        assert_eq!(data.len(), page_size, "Input must be exactly page_size");
        assert!(page_size > Self::OVERHEAD, "Page size must be > {} bytes", Self::OVERHEAD);

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
}
