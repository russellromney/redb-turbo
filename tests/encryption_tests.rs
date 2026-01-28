//! Integration tests for page-level encryption
use redb_turbo as redb;
use redb::{Aes256GcmPageCrypto, Database, ReadableTable, ReadableTableMetadata, TableDefinition};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("test_table");
const U64_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("u64_table");

fn create_tempfile() -> tempfile::NamedTempFile {
    if cfg!(target_os = "wasi") {
        tempfile::NamedTempFile::new_in("/tmp").unwrap()
    } else {
        tempfile::NamedTempFile::new().unwrap()
    }
}

fn create_crypto(key: &[u8; 32]) -> Aes256GcmPageCrypto {
    Aes256GcmPageCrypto::new(key, true).with_skip_below_offset(4096)
}

#[test]
fn encrypted_roundtrip() {
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
            table.insert("hello", "world").unwrap();
            table.insert("secret", "password123").unwrap();
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
        assert_eq!(table.get("hello").unwrap().unwrap().value(), "world");
        assert_eq!(table.get("secret").unwrap().unwrap().value(), "password123");
    }
}

#[test]
fn wrong_key_fails() {
    let tmpfile = create_tempfile();
    let key1 = [0x42u8; 32];
    let key2 = [0x99u8; 32];

    // Write data with key1
    {
        let crypto = create_crypto(&key1);
        let db = Database::builder()
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
    let crypto = create_crypto(&key2);
    let result = Database::builder()
        .set_page_crypto(crypto)
        .open(tmpfile.path());

    // Opening with wrong key should fail (decryption error)
    assert!(result.is_err(), "Opening with wrong key should fail");
}

#[test]
fn data_not_plaintext_on_disk() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];
    let secret_data = "SUPER_SECRET_PLAINTEXT_DATA_12345";

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
        "Plaintext should not be visible in encrypted database file"
    );
}

#[test]
fn large_data_encryption() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Create large data that spans multiple pages
    let large_value: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    // Write large data
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
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
        let crypto = create_crypto(&key);
        let db = Database::builder()
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
fn multiple_tables_encrypted() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    const TABLE_A: TableDefinition<&str, &str> = TableDefinition::new("table_a");
    const TABLE_B: TableDefinition<&str, &str> = TableDefinition::new("table_b");

    // Write to multiple tables
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
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
        let crypto = create_crypto(&key);
        let db = Database::builder()
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
fn transaction_rollback_encrypted() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let crypto = create_crypto(&key);
    let db = Database::builder()
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

#[test]
fn many_small_writes_encrypted() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let crypto = create_crypto(&key);
    let db = Database::builder()
        .set_page_crypto(crypto)
        .create(tmpfile.path())
        .unwrap();

    // Many small writes in separate transactions
    for i in 0..100 {
        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(U64_TABLE).unwrap();
            let value = format!("value_{}", i);
            table.insert(i, value.as_bytes()).unwrap();
        }
        write_txn.commit().unwrap();
    }

    // Verify all data
    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(U64_TABLE).unwrap();
    for i in 0..100 {
        let expected = format!("value_{}", i);
        let retrieved = table.get(i).unwrap().unwrap();
        assert_eq!(retrieved.value(), expected.as_bytes());
    }
}

#[test]
fn batch_writes_encrypted() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let crypto = create_crypto(&key);
    let db = Database::builder()
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
fn update_and_delete_encrypted() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let crypto = create_crypto(&key);
    let db = Database::builder()
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
fn iteration_encrypted() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    let crypto = create_crypto(&key);
    let db = Database::builder()
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

#[cfg(not(target_os = "wasi"))]
#[test]
fn concurrent_reads_encrypted() {
    use std::sync::Arc;
    use std::thread;

    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];
    let path = tmpfile.path().to_path_buf();

    // Write initial data
    {
        let crypto = create_crypto(&key);
        let db = Database::builder()
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
    let crypto = create_crypto(&key);
    let db = Arc::new(
        Database::builder()
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
fn reopen_multiple_times_encrypted() {
    let tmpfile = create_tempfile();
    let key = [0x42u8; 32];

    // Write and close multiple times
    for i in 0..5 {
        let crypto = create_crypto(&key);
        let db = if i == 0 {
            Database::builder()
                .set_page_crypto(crypto)
                .create(tmpfile.path())
                .unwrap()
        } else {
            Database::builder()
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
    let crypto = create_crypto(&key);
    let db = Database::builder()
        .set_page_crypto(crypto)
        .open(tmpfile.path())
        .unwrap();

    let read_txn = db.begin_read().unwrap();
    let table = read_txn.open_table(U64_TABLE).unwrap();

    for i in 0..5 {
        let expected = format!("iteration_{}", i);
        let retrieved = table.get(i).unwrap().unwrap();
        assert_eq!(retrieved.value(), expected.as_bytes());
    }
}
