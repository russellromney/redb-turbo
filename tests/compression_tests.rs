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

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn edge_case_empty_table() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Create DB with compression+encryption but no data
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
            // Just open the table, don't insert anything
            let _table = write_txn.open_table(TABLE).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Reopen and verify empty table works
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
        assert_eq!(table.len().unwrap(), 0);
        assert!(table.get("nonexistent").unwrap().is_none());
    }
}

#[test]
fn edge_case_single_byte_data() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Single byte key and value
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
            table.insert(0, &[0x42u8][..]).unwrap();
            table.insert(1, &[0x00u8][..]).unwrap();
            table.insert(2, &[0xFFu8][..]).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify
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
        assert_eq!(table.get(0).unwrap().unwrap().value(), &[0x42u8]);
        assert_eq!(table.get(1).unwrap().unwrap().value(), &[0x00u8]);
        assert_eq!(table.get(2).unwrap().unwrap().value(), &[0xFFu8]);
    }
}

#[test]
fn edge_case_incompressible_random_data() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Generate pseudo-random incompressible data
    let random_data: Vec<u8> = (0..4000)
        .map(|i| ((i * 17 + 31) ^ (i * 13 + 7)) as u8)
        .collect();

    // Write incompressible data
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
            table.insert(1, random_data.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify data is still retrievable (compression falls back to uncompressed)
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
        assert_eq!(table.get(1).unwrap().unwrap().value(), random_data.as_slice());
    }
}

#[test]
fn edge_case_exact_page_boundary_data() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Data exactly at page boundary (4096 bytes)
    let page_size_data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();

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
            table.insert(1, page_size_data.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify
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
        assert_eq!(table.get(1).unwrap().unwrap().value(), page_size_data.as_slice());
    }
}

#[test]
fn negative_open_encrypted_db_without_encryption() {
    use std::panic;

    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Create encrypted database
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("secret", "data").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Try to open without encryption - should fail (panic or error)
    // This verifies that encrypted data is protected
    let path = tmpfile.path().to_path_buf();
    let result = panic::catch_unwind(move || {
        let db = Database::open(&path)?;
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(TABLE)?;
        let value = table.get("secret")?;
        Ok::<_, redb::Error>(value.map(|v| v.value().to_string()))
    });

    // Should either panic (caught) or return error
    // Success reading correct data would be a security failure
    let failed = match result {
        Err(_) => true, // Panicked - good
        Ok(Err(_)) => true, // Returned error - good
        Ok(Ok(None)) => true, // Data not found - acceptable
        Ok(Ok(Some(val))) => val != "data", // Wrong data - acceptable
    };

    assert!(
        failed,
        "Opening encrypted DB without key should not return correct data"
    );
}

#[test]
fn negative_open_compressed_db_without_compression() {
    use std::panic;

    let tmpfile = create_tempfile();

    // Create compressed database with significant data
    {
        let compression = create_compression();
        let db = Database::builder()
            .set_page_compression(compression)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            // Write enough data to trigger compression
            for i in 0..100u64 {
                let data: Vec<u8> = (0..1000).map(|j| ((i as usize + j) % 64) as u8).collect();
                table.insert(i, data.as_slice()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Try to open without compression - should fail (panic or error)
    let path = tmpfile.path().to_path_buf();
    let expected_data: Vec<u8> = (0..1000).map(|j| (j % 64) as u8).collect();

    let result = panic::catch_unwind(move || {
        let db = Database::open(&path)?;
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(U64_TABLE)?;
        let value = table.get(0u64)?;
        Ok::<_, redb::Error>(value.map(|v| v.value().to_vec()))
    });

    // Should either panic (caught) or return error or wrong data
    let failed = match result {
        Err(_) => true, // Panicked - good
        Ok(Err(_)) => true, // Returned error - good
        Ok(Ok(None)) => true, // Data not found - acceptable
        Ok(Ok(Some(val))) => val != expected_data, // Wrong data - acceptable
    };

    assert!(
        failed,
        "Opening compressed DB without decompression should not return correct data"
    );
}

#[test]
fn edge_case_all_zeros_data() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // All zeros - highly compressible
    let zeros: Vec<u8> = vec![0u8; 10000];

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
            table.insert(1, zeros.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify
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
        assert_eq!(table.get(1).unwrap().unwrap().value(), zeros.as_slice());
    }
}

#[test]
fn edge_case_all_ones_data() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // All 0xFF bytes - highly compressible
    let ones: Vec<u8> = vec![0xFFu8; 10000];

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
            table.insert(1, ones.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify
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
        assert_eq!(table.get(1).unwrap().unwrap().value(), ones.as_slice());
    }
}

// =============================================================================
// Dictionary Compression Integration Tests
// =============================================================================

#[test]
fn dictionary_compression_roundtrip() {
    use redb::{DictionaryTrainer, ZstdDictPageCompression};

    let tmpfile = create_tempfile();

    // Generate sample data for dictionary training
    let samples: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            (0..4096)
                .map(|j| ((i * 3 + j) % 64) as u8)
                .collect()
        })
        .collect();

    // Train dictionary
    let dict = DictionaryTrainer::train(&samples, 8192).unwrap();

    // Write with dictionary compression
    {
        let compression = ZstdDictPageCompression::new(&dict, true);
        let db = Database::builder()
            .set_page_compression(compression)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            for i in 0..50 {
                let data: Vec<u8> = (0..1000).map(|j| ((i + j) % 64) as u8).collect();
                table.insert(i, data.as_slice()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Reopen with same dictionary and verify
    {
        let compression = ZstdDictPageCompression::new(&dict, true);
        let db = Database::builder()
            .set_page_compression(compression)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(U64_TABLE).unwrap();

        for i in 0..50 {
            let expected: Vec<u8> = (0..1000).map(|j| ((i + j) % 64) as u8).collect();
            let retrieved = table.get(i).unwrap().unwrap();
            assert_eq!(retrieved.value(), expected.as_slice());
        }
    }
}

#[test]
fn dictionary_compression_with_encryption() {
    use redb::{DictionaryTrainer, ZstdDictPageCompression};

    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Generate sample data for dictionary training
    let samples: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            (0..4096)
                .map(|j| ((i * 3 + j) % 64) as u8)
                .collect()
        })
        .collect();

    // Train dictionary
    let dict = DictionaryTrainer::train(&samples, 8192).unwrap();

    // Write with dictionary compression + encryption
    {
        let compression = ZstdDictPageCompression::new(&dict, true);
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("secret", "dictionary_compressed_and_encrypted").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify plaintext not on disk
    let file_contents = std::fs::read(tmpfile.path()).unwrap();
    let contains_plaintext = file_contents
        .windows("dictionary_compressed".len())
        .any(|w| w == b"dictionary_compressed");
    assert!(!contains_plaintext, "Plaintext should not be in file");

    // Reopen and verify
    {
        let compression = ZstdDictPageCompression::new(&dict, true);
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .open(tmpfile.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(
            table.get("secret").unwrap().unwrap().value(),
            "dictionary_compressed_and_encrypted"
        );
    }
}

// =============================================================================
// Compaction Tests
// =============================================================================

#[test]
fn compaction_with_compression() {
    let tmpfile = create_tempfile();

    let compression = create_compression();
    let mut db = Database::builder()
        .set_page_compression(compression)
        .create(tmpfile.path())
        .unwrap();

    let big_value = vec![0u8; 100 * 1024]; // 100KB

    // Insert 10MB of data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..100 {
            table.insert(i, big_value.as_slice()).unwrap();
        }
    }
    write_txn.commit().unwrap();

    let file_size_before_delete = std::fs::metadata(tmpfile.path()).unwrap().len();

    // Delete all data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..100 {
            table.remove(i).unwrap();
        }
    }
    write_txn.commit().unwrap();

    // File size should still be large (pages not reclaimed yet)
    let file_size_after_delete = std::fs::metadata(tmpfile.path()).unwrap().len();
    assert!(
        file_size_after_delete >= file_size_before_delete / 2,
        "File should not shrink much before compaction"
    );

    // Compact
    let compacted = db.compact().unwrap();
    assert!(compacted, "Compaction should have made progress");

    // File size should be significantly smaller
    let file_size_after_compact = std::fs::metadata(tmpfile.path()).unwrap().len();
    assert!(
        file_size_after_compact < file_size_before_delete / 2,
        "File should be much smaller after compaction: before={}, after={}",
        file_size_before_delete,
        file_size_after_compact
    );
}

#[test]
fn compaction_with_encryption() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let crypto = create_crypto(&key);
    let mut db = Database::builder()
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    let big_value = vec![0u8; 100 * 1024];

    // Insert 10MB of data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..100 {
            table.insert(i, big_value.as_slice()).unwrap();
        }
    }
    write_txn.commit().unwrap();

    let file_size_before_delete = std::fs::metadata(tmpfile.path()).unwrap().len();

    // Delete all data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..100 {
            table.remove(i).unwrap();
        }
    }
    write_txn.commit().unwrap();

    // Compact
    let compacted = db.compact().unwrap();
    assert!(compacted, "Compaction should have made progress");

    let file_size_after_compact = std::fs::metadata(tmpfile.path()).unwrap().len();
    assert!(
        file_size_after_compact < file_size_before_delete / 2,
        "File should be smaller after compaction"
    );
}

#[test]
fn compaction_with_compression_and_encryption() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let compression = create_compression();
    let crypto = create_crypto(&key);
    let mut db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    let big_value = vec![0u8; 100 * 1024];

    // Insert 10MB of data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..100 {
            table.insert(i, big_value.as_slice()).unwrap();
        }
    }
    write_txn.commit().unwrap();

    let file_size_before_delete = std::fs::metadata(tmpfile.path()).unwrap().len();

    // Delete all data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..100 {
            table.remove(i).unwrap();
        }
    }
    write_txn.commit().unwrap();

    // Compact
    let compacted = db.compact().unwrap();
    assert!(compacted, "Compaction should have made progress");

    let file_size_after_compact = std::fs::metadata(tmpfile.path()).unwrap().len();
    assert!(
        file_size_after_compact < file_size_before_delete / 2,
        "File should be smaller after compaction"
    );

    // Verify we can still read the table (even though it's empty)
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(U64_TABLE).unwrap();
    assert_eq!(table.len().unwrap(), 0);
}

#[test]
fn compaction_preserves_data_with_encryption() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let compression = create_compression();
    let crypto = create_crypto(&key);
    let mut db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    // Insert data
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in 0..100 {
            let value = format!("value_{}", i);
            table.insert(i, value.as_bytes()).unwrap();
        }
    }
    write_txn.commit().unwrap();

    // Delete half the data to create fragmentation
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(U64_TABLE).unwrap();
        for i in (0..100).step_by(2) {
            table.remove(i).unwrap();
        }
    }
    write_txn.commit().unwrap();

    // Compact
    let _compacted = db.compact().unwrap();

    // Verify remaining data is intact
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(U64_TABLE).unwrap();
    assert_eq!(table.len().unwrap(), 50);

    for i in (1..100).step_by(2) {
        let expected = format!("value_{}", i);
        let retrieved = table.get(i).unwrap().unwrap();
        assert_eq!(retrieved.value(), expected.as_bytes());
    }
}

#[test]
fn compaction_reopen_after_compact() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Create, populate, delete, compact
    {
        let compression = create_compression();
        let crypto = create_crypto(&key);
        let mut db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(crypto)
            .create(tmpfile.path())
            .unwrap();

        let big_value = vec![0u8; 100 * 1024];
        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            for i in 0..50 {
                table.insert(i, big_value.as_slice()).unwrap();
            }
        }
        write_txn.commit().unwrap();

        // Keep some data
        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            for i in 10..50 {
                table.remove(i).unwrap();
            }
        }
        write_txn.commit().unwrap();

        // Compact
        db.compact().unwrap();
    }

    // Reopen and verify data
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
        assert_eq!(table.len().unwrap(), 10);

        for i in 0..10 {
            let value = table.get(i).unwrap().unwrap();
            assert_eq!(value.value().len(), 100 * 1024);
        }
    }
}

// =============================================================================
// Key Rotation Tests
// =============================================================================

#[test]
fn key_rotation_change_encryption_key() {
    let source_file = create_tempfile();
    let target_file = create_tempfile();
    let old_key = [0x42u8; 32];
    let new_key = [0x99u8; 32];

    // Create source database with old key
    {
        let crypto = create_crypto(&old_key);
        let db = Database::builder()
            .set_page_crypto(crypto)
            .create(source_file.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("secret1", "value1").unwrap();
            table.insert("secret2", "value2").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Rotate: open source with old key, create target with new key, copy data
    {
        let old_crypto = create_crypto(&old_key);
        let source_db = Database::builder()
            .set_page_crypto(old_crypto)
            .open(source_file.path())
            .unwrap();

        let new_crypto = create_crypto(&new_key);
        let target_db = Database::builder()
            .set_page_crypto(new_crypto)
            .create(target_file.path())
            .unwrap();

        // Copy all data
        let read_txn = source_db.begin_read().unwrap();
        let source_table = read_txn.open_table(TABLE).unwrap();

        let write_txn = target_db.begin_write().unwrap();
        {
            let mut target_table = write_txn.open_table(TABLE).unwrap();
            for entry in source_table.iter().unwrap() {
                let (key, value) = entry.unwrap();
                target_table.insert(key.value(), value.value()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Verify target database works with new key
    {
        let new_crypto = create_crypto(&new_key);
        let db = Database::builder()
            .set_page_crypto(new_crypto)
            .open(target_file.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(table.get("secret1").unwrap().unwrap().value(), "value1");
        assert_eq!(table.get("secret2").unwrap().unwrap().value(), "value2");
    }

    // Verify old key doesn't work on new database
    {
        let old_crypto = create_crypto(&old_key);
        let result = Database::builder()
            .set_page_crypto(old_crypto)
            .open(target_file.path());
        assert!(result.is_err(), "Old key should not work on rotated database");
    }
}

#[test]
fn key_rotation_unencrypted_to_encrypted() {
    let source_file = create_tempfile();
    let target_file = create_tempfile();
    let key = [0x42u8; 32];

    // Create source database without encryption
    {
        let db = Database::create(source_file.path()).unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("plain1", "value1").unwrap();
            table.insert("plain2", "value2").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Migrate to encrypted database
    {
        let source_db = Database::open(source_file.path()).unwrap();

        let crypto = create_crypto(&key);
        let target_db = Database::builder()
            .set_page_crypto(crypto)
            .create(target_file.path())
            .unwrap();

        // Copy all data
        let read_txn = source_db.begin_read().unwrap();
        let source_table = read_txn.open_table(TABLE).unwrap();

        let write_txn = target_db.begin_write().unwrap();
        {
            let mut target_table = write_txn.open_table(TABLE).unwrap();
            for entry in source_table.iter().unwrap() {
                let (key, value) = entry.unwrap();
                target_table.insert(key.value(), value.value()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Verify target is encrypted (plaintext not on disk)
    let file_contents = std::fs::read(target_file.path()).unwrap();
    let contains_plaintext = file_contents
        .windows("value1".len())
        .any(|w| w == b"value1");
    assert!(!contains_plaintext, "Plaintext should not be in encrypted file");

    // Verify we can read with the key
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_crypto(crypto)
            .open(target_file.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(table.get("plain1").unwrap().unwrap().value(), "value1");
        assert_eq!(table.get("plain2").unwrap().unwrap().value(), "value2");
    }
}

#[test]
fn key_rotation_encrypted_to_unencrypted() {
    let source_file = create_tempfile();
    let target_file = create_tempfile();
    let key = [0x42u8; 32];

    // Create source database with encryption
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
            .set_page_crypto(crypto)
            .create(source_file.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(TABLE).unwrap();
            table.insert("secret1", "decrypted_value1").unwrap();
            table.insert("secret2", "decrypted_value2").unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Migrate to unencrypted database
    {
        let crypto = create_crypto(&key);
        let source_db = Database::builder()
            .set_page_crypto(crypto)
            .open(source_file.path())
            .unwrap();

        let target_db = Database::create(target_file.path()).unwrap();

        // Copy all data
        let read_txn = source_db.begin_read().unwrap();
        let source_table = read_txn.open_table(TABLE).unwrap();

        let write_txn = target_db.begin_write().unwrap();
        {
            let mut target_table = write_txn.open_table(TABLE).unwrap();
            for entry in source_table.iter().unwrap() {
                let (k, v) = entry.unwrap();
                target_table.insert(k.value(), v.value()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Verify target is readable without encryption
    {
        let db = Database::open(target_file.path()).unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(TABLE).unwrap();
        assert_eq!(table.get("secret1").unwrap().unwrap().value(), "decrypted_value1");
        assert_eq!(table.get("secret2").unwrap().unwrap().value(), "decrypted_value2");
    }
}

#[test]
fn key_rotation_with_compression_change() {
    let source_file = create_tempfile();
    let target_file = create_tempfile();
    let old_key = [0x42u8; 32];
    let new_key = [0x99u8; 32];

    // Create source: encrypted, no compression
    {
        let crypto = create_crypto(&old_key);
        let db = Database::builder()
            .set_page_crypto(crypto)
            .create(source_file.path())
            .unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            for i in 0..50 {
                let value = format!("data_{}", i);
                table.insert(i, value.as_bytes()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Migrate to: new key + compression
    {
        let old_crypto = create_crypto(&old_key);
        let source_db = Database::builder()
            .set_page_crypto(old_crypto)
            .open(source_file.path())
            .unwrap();

        let compression = create_compression();
        let new_crypto = create_crypto(&new_key);
        let target_db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(new_crypto)
            .create(target_file.path())
            .unwrap();

        // Copy all data
        let read_txn = source_db.begin_read().unwrap();
        let source_table = read_txn.open_table(U64_TABLE).unwrap();

        let write_txn = target_db.begin_write().unwrap();
        {
            let mut target_table = write_txn.open_table(U64_TABLE).unwrap();
            for entry in source_table.iter().unwrap() {
                let (key, value) = entry.unwrap();
                target_table.insert(key.value(), value.value()).unwrap();
            }
        }
        write_txn.commit().unwrap();
    }

    // Verify target database with new settings
    {
        let compression = create_compression();
        let new_crypto = create_crypto(&new_key);
        let db = Database::builder()
            .set_page_compression(compression)
            .set_page_crypto(new_crypto)
            .open(target_file.path())
            .unwrap();

        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(U64_TABLE).unwrap();
        assert_eq!(table.len().unwrap(), 50);

        for i in 0..50 {
            let expected = format!("data_{}", i);
            let retrieved = table.get(i).unwrap().unwrap();
            assert_eq!(retrieved.value(), expected.as_bytes());
        }
    }
}
