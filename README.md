# redb-turbo

A fork of [redb](https://github.com/cberner/redb) with **page-level encryption**, **compression**, and **io_uring** support.

[![License](https://img.shields.io/crates/l/redb)](https://crates.io/crates/redb)

## What's New

| Feature | Description |
|---------|-------------|
| **Encryption** | AES-256-GCM page-level encryption with deterministic nonces |
| **Compression** | Zstd compression with optional dictionary support |
| **io_uring** | Batched writes on Linux for better throughput (auto-fallback on older kernels) |

All features are **optional** and **backward-compatible** with standard redb databases.

## Quick Start

```rust
use redb::{Database, Error, ReadableTable, TableDefinition};

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

## Encrypted Database

```rust
use redb::{Builder, Database, TableDefinition};
use redb::page_crypto::Aes256GcmPageCrypto;

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("secrets");

fn main() -> Result<(), redb::Error> {
    // 32-byte key for AES-256
    let key = b"super_secret_key_32_bytes_long!!";

    let crypto = Aes256GcmPageCrypto::new(key)
        .with_compression(3);  // zstd level 1-22

    let db = Builder::new()
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

Enable with the `encryption` feature:
```toml
[dependencies]
redb = { git = "https://github.com/russellromney/redb-turbo", features = ["encryption"] }
```

## Features

**From original redb:**
* Zero-copy, thread-safe, `BTreeMap` based API
* Fully ACID-compliant transactions
* MVCC support for concurrent readers & writer, without blocking
* Crash-safe by default
* Savepoints and rollbacks

**Added in redb-turbo:**
* Page-level AES-256-GCM encryption (transparent to application)
* Zstd compression with configurable level and dictionary support
* io_uring batched writes on Linux (automatic runtime detection)
* `write_batch()` API for custom storage backends

## io_uring Performance

On Linux with kernel 5.1+, write operations are automatically batched using io_uring:

```
flush_write_buffer()
  │
  ├─► Collect all dirty pages
  │
  ├─► Submit batch to io_uring ring
  │
  └─► Wait for completions
```

Falls back gracefully to standard pwrite on:
- macOS, BSD, Windows
- Older Linux kernels
- Containers without io_uring permissions

## Cargo Features

| Feature | Description |
|---------|-------------|
| `encryption` | Enable AES-256-GCM encryption and zstd compression |
| `logging` | Enable log messages |
| `cache_metrics` | Enable cache hit/miss metrics |

## Benchmarks

See original [redb benchmarks](https://github.com/cberner/redb#benchmarks). io_uring improvements are most noticeable on write-heavy workloads with many pages per transaction.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

## Credits

Based on [redb](https://github.com/cberner/redb) by Christopher Berner.
