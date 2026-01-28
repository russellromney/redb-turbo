//! Example demonstrating encrypted database usage
use redb_turbo as redb;
use redb::{Aes256GcmPageCrypto, Database, ReadableTable, TableDefinition};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("my_data");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create encryption key (in practice, derive from password or use KMS)
    let key = [0x42u8; 32];

    // Create crypto provider, skip header page
    let crypto = Aes256GcmPageCrypto::new(&key, true)
        .with_skip_below_offset(4096); // Skip first page (header)

    let tmpfile = tempfile::NamedTempFile::new()?;
    let path = tmpfile.path();

    // Create encrypted database
    {
        let db = Database::builder()
            .set_page_crypto(crypto)
            .create(path)?;

        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE)?;
            table.insert("hello", "world")?;
            table.insert("secret", "this data is encrypted on disk!")?;
        }
        write_txn.commit()?;
        println!("Data written to encrypted database");
    }

    // Verify data on disk is NOT plaintext
    let file_contents = std::fs::read(path)?;
    let contains_plaintext = file_contents
        .windows(b"this data is encrypted".len())
        .any(|w| w == b"this data is encrypted");

    if contains_plaintext {
        println!("ERROR: Found plaintext in encrypted database file!");
        return Err("Encryption failed - plaintext found in file".into());
    } else {
        println!("SUCCESS: No plaintext found in database file (data is encrypted)");
    }

    // Re-open with same key and verify data
    let crypto2 = Aes256GcmPageCrypto::new(&key, true)
        .with_skip_below_offset(4096);

    let db = Database::builder()
        .set_page_crypto(crypto2)
        .open(path)?;

    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(TABLE)?;

    let hello = table.get("hello")?.unwrap();
    let secret = table.get("secret")?.unwrap();

    println!("Read back: hello={}, secret={}", hello.value(), secret.value());

    assert_eq!(hello.value(), "world");
    assert_eq!(secret.value(), "this data is encrypted on disk!");

    println!("All encryption tests passed!");
    Ok(())
}
