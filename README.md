# redb-turbo

A fork of [redb](https://github.com/cberner/redb) with **AES-256-GCM page encryption** and **zstd page compression**.

[![Crates.io](https://img.shields.io/crates/v/redb-turbo.svg)](https://crates.io/crates/redb-turbo)
[![License](https://img.shields.io/crates/l/redb-turbo)](https://crates.io/crates/redb-turbo)

## Features

- **Encryption**: AES-256-GCM encryption at the page level for data-at-rest protection
- **Compression**: Zstd compression at the page level to reduce storage size
- **Dictionary Compression**: Train custom zstd dictionaries for 20-50% better compression ratios
- **Flexible**: Use nothing, compression only, encryption only, or both
- **Compatible**: Same API as redb - just add encryption/compression to your builder

## Installation

```bash
cargo add redb-turbo
```

## Usage

### Plain redb (no encryption or compression)

```rust
use redb_turbo::Database;

let db = Database::create("plain.redb")?;
```

### Encryption Only

```rust
use redb_turbo::{Database, Aes256GcmPageCrypto, TableDefinition};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("secrets");

fn main() -> Result<(), redb_turbo::Error> {
    let key: [u8; 32] = [0u8; 32]; // your 32-byte key

    let crypto = Aes256GcmPageCrypto::new(&key, true); // true = skip header page

    let db = Database::builder()
        .set_page_crypto(crypto)
        .create("encrypted.redb")?;

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(TABLE)?;
        table.insert("api_key", "sk-1234567890")?;
    }
    write_txn.commit()?;

    Ok(())
}
```

### Compression Only

```rust
use redb_turbo::{Database, ZstdPageCompression, TableDefinition};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("data");

fn main() -> Result<(), redb_turbo::Error> {
    let compression = ZstdPageCompression::new(true); // true = skip header page

    let db = Database::builder()
        .set_page_compression(compression)
        .create("compressed.redb")?;

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(TABLE)?;
        table.insert("key", "highly compressible data data data data")?;
    }
    write_txn.commit()?;

    Ok(())
}
```

### Compression + Encryption

For maximum security and storage efficiency, use both. Data is compressed first, then encrypted.

```rust
use redb_turbo::{Database, Aes256GcmPageCrypto, ZstdPageCompression, TableDefinition};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("secrets");

fn main() -> Result<(), redb_turbo::Error> {
    let key: [u8; 32] = [0u8; 32]; // your 32-byte key

    let compression = ZstdPageCompression::new(true);
    let crypto = Aes256GcmPageCrypto::new(&key, true);

    let db = Database::builder()
        .set_page_compression(compression)
        .set_page_crypto(crypto)
        .create("secure.redb")?;

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(TABLE)?;
        table.insert("api_key", "sk-1234567890")?;
    }
    write_txn.commit()?;

    Ok(())
}
```

### Dictionary Compression (Advanced)

For better compression ratios on small pages, train a zstd dictionary on sample data from your workload:

```rust
use redb_turbo::{Database, ZstdDictPageCompression, DictionaryTrainer, TableDefinition};

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("data");

fn main() -> Result<(), redb_turbo::Error> {
    // Step 1: Collect sample pages from an existing database or representative data
    let samples: Vec<Vec<u8>> = collect_sample_pages(); // Your data collection logic

    // Step 2: Train a dictionary (64KB is good for 4KB pages)
    let dict = DictionaryTrainer::train(&samples, 65536)
        .expect("Need at least 100 samples for good results");

    // Step 3: Save dictionary for reuse
    DictionaryTrainer::save_to_file(&dict, "my_dict.zdict")?;

    // Step 4: Use dictionary compression
    let compression = ZstdDictPageCompression::new(&dict, true);
    let db = Database::builder()
        .set_page_compression(compression)
        .create("dict_compressed.redb")?;

    // Use normally...
    Ok(())
}

// Later, load the dictionary:
fn open_with_dict() -> Result<(), redb_turbo::Error> {
    let dict = DictionaryTrainer::load_from_file("my_dict.zdict")?;
    let compression = ZstdDictPageCompression::new(&dict, true);
    let db = Database::builder()
        .set_page_compression(compression)
        .open("dict_compressed.redb")?;
    Ok(())
}
```

Dictionary compression typically improves ratios by 20-50% for small blocks. Use `DictionaryTrainer::estimate_improvement()` to measure the benefit for your data.

## How It Works

### Encryption

We reserve 28 bytes per page for encryption overhead (~0.7% space for 4KB pages). This includes a 12-byte random nonce generated per write and a 16-byte authentication tag that detects tampering. The database header page is left unencrypted for bootstrapping.

### Compression

Each page is independently compressed using zstd. If compression doesn't reduce size, the page is stored uncompressed with a marker. The header page is left uncompressed for bootstrapping.

### Dictionary Compression

When using a pre-trained dictionary, zstd can reference common patterns without including them in each compressed block, significantly improving ratios for small pages. The dictionary must be available when opening the database.

---

# Original redb Documentation

Everything below is from the original [redb](https://github.com/cberner/redb) project.

---

A simple, portable, high-performance, ACID, embedded key-value store.

redb is written in pure Rust and is loosely inspired by [lmdb](http://www.lmdb.tech/doc/). Data is stored in a collection
of copy-on-write B-trees. For more details, see the [design doc](docs/design.md)

```rust
use redb::{Database, Error, ReadableDatabase, TableDefinition};

const TABLE: TableDefinition<&str, u64> = TableDefinition::new("my_data");

fn main() -> Result<(), Error> {
    let db = Database::create("my_db.redb")?;
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(TABLE)?;
        table.insert("my_key", &123)?;
    }
    write_txn.commit()?;

    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(TABLE)?;
    assert_eq!(table.get("my_key")?.unwrap().value(), 123);

    Ok(())
}
```

## Status
Stable and maintained.

The file format is stable, and a reasonable effort will be made to provide an upgrade path if there
are any future changes to it.

## Features
* Zero-copy, thread-safe, `BTreeMap` based API
* Fully ACID-compliant transactions
* MVCC support for concurrent readers & writer, without blocking
* Crash-safe by default
* Savepoints and rollbacks

## Development
To run all the tests and benchmarks a few extra dependencies are required:
* `cargo install cargo-deny --locked`
* `cargo install cargo-fuzz --locked`
* `apt install libclang-dev`

## Benchmarks
redb has similar performance to other top embedded key-value stores such as lmdb and rocksdb

|                           | redb      | lmdb       | rocksdb        | sled     | fjall       | sqlite     |
|---------------------------|-----------|------------|----------------|----------|-------------|------------|
| bulk load                 | 17063ms   | **9232ms** | 13969ms        | 24971ms  | 18619ms     | 15341ms    |
| individual writes         | **920ms** | 1598ms     | 2432ms         | 2701ms   | 3488ms      | 7040ms     |
| batch writes              | 1595ms    | 942ms      | 451ms          | 853ms    | **353ms**   | 2625ms     |
| len()                     | **0ms**   | **0ms**    | 749ms          | 1573ms   | 1181ms      | 30ms       |
| random reads              | 1138ms    | **637ms**  | 2911ms         | 1601ms   | 2177ms      | 4283ms     |
| random reads              | 934ms     | **631ms**  | 2884ms         | 1592ms   | 2357ms      | 4281ms     |
| random range reads        | 1174ms    | **565ms**  | 2734ms         | 1992ms   | 2564ms      | 8431ms     |
| random range reads        | 1173ms    | **565ms**  | 2742ms         | 1993ms   | 2690ms      | 8449ms     |
| random reads (4 threads)  | 1390ms    | **840ms**  | 3995ms         | 1913ms   | 2606ms      | 7000ms     |
| random reads (8 threads)  | 757ms     | **427ms**  | 2147ms         | 1019ms   | 1352ms      | 8123ms     |
| random reads (16 threads) | 652ms     | **216ms**  | 1478ms         | 690ms    | 963ms       | 23022ms    |
| random reads (32 threads) | 410ms     | **125ms**  | 1100ms         | 444ms    | 576ms       | 26536ms    |
| removals                  | 23297ms   | 10435ms    | 6900ms         | 11088ms  | **6004ms**  | 10323ms    |
| uncompacted size          | 4.00 GiB  | 2.61 GiB   | **893.18 MiB** | 2.13 GiB | 1000.95 MiB | 1.09 GiB   |
| compacted size            | 1.69 GiB  | 1.26 GiB   | **454.71 MiB** | N/A      | 1000.95 MiB | 556.85 MiB |

Source code for benchmark [here](./crates/redb-bench/benches/lmdb_benchmark.rs). Results collected on a Ryzen 9950X3D with Samsung 9100 PRO NVMe.

## License

Licensed under either of

* [Apache License, Version 2.0](LICENSE-APACHE)
* [MIT License](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
