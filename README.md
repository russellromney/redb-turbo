# redb-turbo

A fork of [redb](https://github.com/cberner/redb) with **AES-256-GCM encryption** and **zstd compression**.

## Installation

```toml
[dependencies]
redb-turbo = "0.1"
```

## Usage

```rust
use redb_turbo::{Builder, Database, TableDefinition};
use redb_turbo::page_crypto::Aes256GcmPageCrypto;

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("secrets");

fn main() -> Result<(), redb_turbo::Error> {
    let key: [u8; 32] = /* your 32-byte key */;

    let crypto = Aes256GcmPageCrypto::new(&key, true)
        .with_skip_below_offset(4096);

    let db = Builder::new()
        .set_page_crypto(crypto)
        .create("encrypted.redb")?;

    // Use normally - encryption is transparent
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(TABLE)?;
        table.insert("api_key", "sk-1234567890")?;
    }
    write_txn.commit()?;

    Ok(())
}
```

## How It Works

Each 4KB page is encrypted independently:

```
[nonce: 12 bytes][ciphertext: 4068 bytes][auth tag: 16 bytes]
```

- **28 bytes overhead per page** (~0.7% space)
- **Nonce**: Derived from page offset (deterministic, no storage needed)
- **Auth tag**: GCM authentication tag that detects tampering/bit-flips
- **Header page**: Left unencrypted for database bootstrapping

## Development

Requires Rust 1.85+.

```bash
cargo build
cargo test
cargo bench --bench lmdb_benchmark
```

## License

[Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT). Based on [redb](https://github.com/cberner/redb) by Christopher Berner.
