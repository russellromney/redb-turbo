// Benchmark for high-concurrency write workloads to test io_uring benefit
//
// Run with io_uring:    cargo bench --bench concurrent_writes_benchmark
// Run without io_uring: REDB_DISABLE_IOURING=1 cargo bench --bench concurrent_writes_benchmark

use redb::{Database, TableDefinition};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("data");

fn benchmark_concurrent_writes(num_threads: usize, writes_per_thread: usize, value_size: usize) -> Duration {
    let tmpfile = NamedTempFile::new().unwrap();
    let db = Arc::new(Database::create(tmpfile.path()).unwrap());

    // Pre-create table
    {
        let write_txn = db.begin_write().unwrap();
        write_txn.open_table(TABLE).unwrap();
        write_txn.commit().unwrap();
    }

    let value = vec![0xABu8; value_size];
    let start = Instant::now();

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let db = Arc::clone(&db);
            let value = value.clone();
            thread::spawn(move || {
                let base = thread_id * writes_per_thread;
                for i in 0..writes_per_thread {
                    let write_txn = db.begin_write().unwrap();
                    {
                        let mut table = write_txn.open_table(TABLE).unwrap();
                        table.insert((base + i) as u64, value.as_slice()).unwrap();
                    }
                    write_txn.commit().unwrap();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    start.elapsed()
}

fn benchmark_batch_writes(num_threads: usize, batches_per_thread: usize, writes_per_batch: usize, value_size: usize) -> Duration {
    let tmpfile = NamedTempFile::new().unwrap();
    let db = Arc::new(Database::create(tmpfile.path()).unwrap());

    // Pre-create table
    {
        let write_txn = db.begin_write().unwrap();
        write_txn.open_table(TABLE).unwrap();
        write_txn.commit().unwrap();
    }

    let value = vec![0xABu8; value_size];
    let start = Instant::now();

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let db = Arc::clone(&db);
            let value = value.clone();
            thread::spawn(move || {
                let base = thread_id * batches_per_thread * writes_per_batch;
                for batch in 0..batches_per_thread {
                    let write_txn = db.begin_write().unwrap();
                    {
                        let mut table = write_txn.open_table(TABLE).unwrap();
                        for i in 0..writes_per_batch {
                            let key = (base + batch * writes_per_batch + i) as u64;
                            table.insert(key, value.as_slice()).unwrap();
                        }
                    }
                    write_txn.commit().unwrap();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    start.elapsed()
}

fn main() {
    let io_uring_disabled = std::env::var("REDB_DISABLE_IOURING").is_ok();
    let mode = if io_uring_disabled { "STANDARD" } else { "IO_URING" };

    println!("\n=== Concurrent Writes Benchmark ({}) ===\n", mode);

    // Test 1: Many small transactions (1 write each)
    println!("Test 1: Single-write transactions (stress commit path)");
    for threads in [1, 2, 4, 8] {
        let writes = 1000;
        let duration = benchmark_concurrent_writes(threads, writes, 1024);
        let total_writes = threads * writes;
        let writes_per_sec = total_writes as f64 / duration.as_secs_f64();
        println!("  {} threads, {} writes each: {:?} ({:.0} writes/sec)",
                 threads, writes, duration, writes_per_sec);
    }

    // Test 2: Batched transactions (many writes per commit)
    println!("\nTest 2: Batched transactions (100 writes per commit)");
    for threads in [1, 2, 4, 8] {
        let batches = 100;
        let writes_per_batch = 100;
        let duration = benchmark_batch_writes(threads, batches, writes_per_batch, 1024);
        let total_writes = threads * batches * writes_per_batch;
        let writes_per_sec = total_writes as f64 / duration.as_secs_f64();
        println!("  {} threads, {} batches x {} writes: {:?} ({:.0} writes/sec)",
                 threads, batches, writes_per_batch, duration, writes_per_sec);
    }

    // Test 3: Large values (more data per write)
    println!("\nTest 3: Large values (4KB each, batched)");
    for threads in [1, 2, 4] {
        let batches = 50;
        let writes_per_batch = 50;
        let duration = benchmark_batch_writes(threads, batches, writes_per_batch, 4096);
        let total_writes = threads * batches * writes_per_batch;
        let total_mb = (total_writes * 4096) as f64 / (1024.0 * 1024.0);
        let mb_per_sec = total_mb / duration.as_secs_f64();
        println!("  {} threads, {} batches x {} writes: {:?} ({:.1} MB/sec)",
                 threads, batches, writes_per_batch, duration, mb_per_sec);
    }

    println!("\nDone!");
}
