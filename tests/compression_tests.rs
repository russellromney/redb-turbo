//! Integration tests for page-level compression and combined compression+encryption
use redb_turbo as redb;
use redb::{
    Aes256GcmPageCrypto, Database, ReadableTable, ReadableTableMetadata, TableDefinition,
    ZstdPageCompression,
};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("test_table");
const U64_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("u64_table");

fn create_tempfile() -> tempfile::NamedTempFile {
    if cfg!(target_os = "wasi") {
        tempfile::NamedTempFile::new_in("/tmp").unwrap()
    } else {
        tempfile::NamedTempFile::new().unwrap()
    }
}

fn create_compression() -> ZstdPageCompression {
    ZstdPageCompression::new(true) // skip header pages
}

fn create_crypto(key: &[u8; 32]) -> Aes256GcmPageCrypto {
    Aes256GcmPageCrypto::new(key, true).with_skip_below_offset(4096)
}

// =============================================================================
// Mode 1: Plain redb (no compression, no encryption)
// =============================================================================

#[test]
fn plain_roundtrip() {
    let tmpfile = create_tempfile();

    // Write data
    {
        let db = Database::create(tmpfile.path()).unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("hello", "world").unwrap();
            table.insert("foo", "bar").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen and verify
    {
        let db = Database::open(tmpfile.path()).unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(table.get("hello").unwrap().unwrap().value(), "world");
        assert_eq!(table.get("foo").unwrap().unwrap().value(), "bar");
    }
}

// =============================================================================
// Mode 2: Compression only
// =============================================================================

#[test]
fn compression_only_roundtrip() {
    let tmpfile = create_tempfile();

    // Write data
    {
        let compression = create_compression();
        let db = Database::builder()
            .set_page_compression(compression)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("hello", "world").unwrap();
            table.insert("compressed", "data").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen with same compression and verify
    {
        let compression = create_compression();
        let db = Database::builder()
            .set_page_compression(compression)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(table.get("hello").unwrap().unwrap().value(), "world");
        assert_eq!(table.get("compressed").unwrap().unwrap().value(), "data");
    }
}

#[test]
fn compression_modifies_page_content() {
    // This test verifies that compression is actually happening by checking
    // that a recognizable repeated pattern isn't stored as-is on disk.
    // Note: File size comparison isn't reliable since redb uses fixed page sizes.

    let tmpfile = create_tempfile();

    // A recognizable repeated pattern that would be visible in raw file
    let pattern = b"COMPRESS_ME_PATTERN_";
    let repeated_pattern: Vec<u8> = pattern.iter().cycle().take(5000).copied().collect();

    // Write with compression
    {
        let compression = create_compression();
        let db = Database::builder()
            .set_page_compression(compression)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            table.insert(1, repeated_pattern.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify the repeated pattern isn't stored verbatim (compression worked)
    let file_contents = std::fs::read(tmpfile.path()).unwrap();

    // Count occurrences of the pattern in the raw file
    // With compression, the repetitions should be compressed away
    let pattern_count = file_contents
        .windows(pattern.len())
        .filter(|w| *w == pattern)
        .count();

    // In uncompressed form, there would be ~250 occurrences (5000/20)
    // With compression, we should see far fewer (maybe 1-2 in metadata, or none)
    assert!(
        pattern_count < 10,
        "Found {} occurrences of pattern - compression may not be working",
        pattern_count
    );

    // Verify we can still read the data back correctly
    {
        let compression = create_compression();
        let db = Database::builder()
            .set_page_compression(compression)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(U64_TABLE).unwrap();
        let retrieved = table.get(1).unwrap().unwrap();
        assert_eq!(retrieved.value(), repeated_pattern.as_slice());
    }
}

#[test]
fn compression_large_data() {
    let tmpfile = create_tempfile();

    // Create large data that spans multiple pages
    let large_value: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    // Write large data
    {
        let compression = create_compression();
        let db = Database::builder()
            .set_page_compression(compression)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            table.insert(1, large_value.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen and verify
    {
        let compression = create_compression();
        let db = Database::builder()
            .set_page_compression(compression)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(U64_TABLE).unwrap();
        let retrieved = table.get(1).unwrap().unwrap();
        assert_eq!(retrieved.value(), large_value.as_slice());
    }
}

// =============================================================================
// Mode 3: Encryption only (these complement encryption_tests.rs)
// =============================================================================

#[test]
fn encryption_only_roundtrip() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Write data
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("secret", "encrypted_value").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen with same key and verify
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_crypto(crypto)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(
            table.get("secret").unwrap().unwrap().value(),
            "encrypted_value"
        );
    }
}

// =============================================================================
// Mode 4: Compression + Encryption (the full combo)
// =============================================================================

#[test]
fn compression_and_encryption_roundtrip() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Write data with both compression and encryption
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("hello", "world").unwrap();
            table.insert("secret", "compressed_and_encrypted").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen with same compression and key, verify
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(table.get("hello").unwrap().unwrap().value(), "world");
        assert_eq!(
            table.get("secret").unwrap().unwrap().value(),
            "compressed_and_encrypted"
        );
    }
}

#[test]
fn compression_and_encryption_large_data() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Large compressible data
    let large_value: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    // Write
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            table.insert(1, large_value.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen and verify
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(U64_TABLE).unwrap();
        let retrieved = table.get(1).unwrap().unwrap();
        assert_eq!(retrieved.value(), large_value.as_slice());
    }
}

#[test]
fn compression_and_encryption_data_not_plaintext() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];
    let secret_data = "SUPER_SECRET_PLAINTEXT_DATA_12345";

    // Write data
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("key", secret_data).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Read raw file and verify plaintext is not present
    let file_contents = std::fs::read(tmpfile.path()).unwrap();
    let contains_plaintext = file_contents
        .windows(secret_data.len())
        .any(|w| w == secret_data.as_bytes());

    assert!(
        !contains_plaintext,
        "Plaintext should not be visible in compressed+encrypted database file"
    );
}

#[test]
fn compression_and_encryption_wrong_key_fails() {
    let tmpfile = create_tempfile();
    let key1 = [0x42u8; 32];
    let key2 = [0x99u8; 32];

    // Write data with key1
    {
        let compression = create_compression();
        let crypto = create_crypto(&key1);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("test", "data").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Try to open with key2 - should fail
    let compression = create_compression();
    let crypto = create_crypto(&key2);
    let result = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .open(tmpfile.path());

    assert!(result.is_err(), "Opening with wrong key should fail");
}

#[test]
fn compression_and_encryption_multiple_tables() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    const TABLE_A: TableDefinition<&str, &str> = TableDefinition::new("table_a");
    const TABLE_B: TableDefinition<&str, &str> = TableDefinition::new("table_b");

    // Write to multiple tables
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table_a = write_txn.open_table(TABLE_A).unwrap();
            table_a.insert("a_key", "a_value").unwrap();

            let mut table_b = write_txn.open_table(TABLE_B).unwrap();
            table_b.insert("b_key", "b_value").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen and verify both tables
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table_a = read_txn.open_table(TABLE_A).unwrap();
        let table_b = read_txn.open_table(TABLE_B).unwrap();

        assert_eq!(table_a.get("a_key").unwrap().unwrap().value(), "a_value");
        assert_eq!(table_b.get("b_key").unwrap().unwrap().value(), "b_value");
    }
}

#[test]
fn compression_and_encryption_batch_writes() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let compression = create_compression();
    let crypto = create_crypto(&key);
    let db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    // Batch write in single transaction
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..1000 {
            let value = format!("batch_value_{}", i);
            table.insert(i, value.as_bytes()).unwrap();
        }
    }
    write_txn.commit().unwrap();

    // Verify all data
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(U64_TABLE).unwrap();
    assert_eq!(table.len().unwrap(), 1000);

    for i in 0..1000 {
        let expected = format!("batch_value_{}", i);
        let retrieved = table.get(i).unwrap().unwrap();
        assert_eq!(retrieved.value(), expected.as_bytes());
    }
}

#[test]
fn compression_and_encryption_iteration() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let compression = create_compression();
    let crypto = create_crypto(&key);
    let db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    // Insert data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..50 {
            table.insert(i, b"test".as_slice()).unwrap();
        }
    }
    write_txn.commit().unwrap();

    // Iterate and count
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(U64_TABLE).unwrap();

    let count = table.iter().unwrap().count();
    assert_eq!(count, 50);

    // Range iteration
    let range_count = table.range(10..20).unwrap().count();
    assert_eq!(range_count, 10);
}

#[test]
fn compression_and_encryption_reopen_multiple_times() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Write and close multiple times
    for i in 0..5u64 {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = if i == 0 {
            Database::builder()
                .set_page_compression(compression)
                .set_page_crypto(crypto)
                .create(tmpfile.path())
                .unwrap()
        } else {
            Database::builder()
                .set_page_compression(compression)
                .set_page_crypto(crypto)
                .open(tmpfile.path())
                .unwrap()
        };

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            let value = format!("iteration_{}", i);
            table.insert(i, value.as_bytes()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Final verification
    let compression = create_compression();
    let crypto = create_crypto(&key);
    let db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .open(tmpfile.path())
        .unwrap();

    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(U64_TABLE).unwrap();

    for i in 0..5u64 {
        let expected = format!("iteration_{}", i);
        let retrieved = table.get(i).unwrap().unwrap();
        assert_eq!(retrieved.value(), expected.as_bytes());
    }
}

#[cfg(not(target_os = "wasi"))]
#[test]
fn compression_and_encryption_concurrent_reads() {
    use std::sync::Arc;
    use std::thread;

    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];
    let path = tmpfile.path().to_path_buf();

    // Write initial data
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(&path)
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            for i in 0..100 {
                table.insert(i, b"concurrent_test".as_slice()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Concurrent reads from multiple threads
    let compression = create_compression();
    let crypto = create_crypto(&key);
    let db = Arc::new(
        Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .open(&path)
            .unwrap(),
    );

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let db = Arc::clone(&db);
            thread::spawn(move || {
                for _ in 0..10 {
                    let read_txn = db.begin_read().unwrap();
                    let table = read_txn.open_table(U64_TABLE).unwrap();
                    for i in 0..100 {
                        let value = table.get(i).unwrap().unwrap();
                        assert_eq!(value.value(), b"concurrent_test");
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn compression_and_encryption_update_and_delete() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let compression = create_compression();
    let crypto = create_crypto(&key);
    let db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    // Insert initial data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(TABLE).unwrap();
        table.insert("key1", "value1").unwrap();
        table.insert("key2", "value2").unwrap();
        table.insert("key3", "value3").unwrap();
    }
    write_txn.commit().unwrap();

    // Update and delete
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(TABLE).unwrap();
        table.insert("key1", "updated_value1").unwrap();
        table.remove("key2").unwrap();
    }
    write_txn.commit().unwrap();

    // Verify
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(TABLE).unwrap();
    assert_eq!(
        table.get("key1").unwrap().unwrap().value(),
        "updated_value1"
    );
    assert!(table.get("key2").unwrap().is_none());
    assert_eq!(table.get("key3").unwrap().unwrap().value(), "value3");
}

#[test]
fn compression_and_encryption_transaction_rollback() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let compression = create_compression();
    let crypto = create_crypto(&key);
    let db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    // Commit first transaction
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(TABLE).unwrap();
        table.insert("committed", "value").unwrap();
    }
    write_txn.commit().unwrap();

    // Start second transaction but don't commit (drop = rollback)
    {
        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("uncommitted", "value").unwrap();
        }
        // Implicit rollback on drop
    }

    // Verify only committed data exists
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(TABLE).unwrap();
    assert!(table.get("committed").unwrap().is_some());
    assert!(table.get("uncommitted").unwrap().is_none());
}
