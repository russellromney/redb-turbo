// Comprehensive concurrent benchmark for redb-turbo
//
// Tests: Plain vs Encrypted (AES-256-GCM with 28-byte overhead per page)
// All tests run for a fixed duration (time-based)
//
// Run:
//   cargo bench --bench concurrent_benchmark
//   cargo bench --bench concurrent_benchmark --features encryption

use redb_turbo as redb;
use redb::{Database, TableDefinition, Aes256GcmPageCrypto};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("data");
const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64];
const WRITES_PER_BATCH: usize = 1000;

#[derive(Clone, Copy)]
enum CryptoMode {
    Plain,
    Encrypted,
}

impl std::fmt::Display for CryptoMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoMode::Plain => write!(f, "Plain"),
            CryptoMode::Encrypted => write!(f, "Encrypted (AES-256-GCM, 28B overhead/page)"),
        }
    }
}

#[derive(Clone)]
struct LatencyStats {
    latencies: Vec<Duration>,
}

impl LatencyStats {
    fn new() -> Self { Self { latencies: Vec::with_capacity(100_000) } }
    fn record(&mut self, d: Duration) { self.latencies.push(d); }
    fn merge(&mut self, other: &LatencyStats) { self.latencies.extend_from_slice(&other.latencies); }
    fn percentile(&mut self, p: f64) -> Duration {
        if self.latencies.is_empty() { return Duration::ZERO; }
        self.latencies.sort();
        let idx = ((self.latencies.len() as f64 * p / 100.0) as usize).min(self.latencies.len() - 1);
        self.latencies[idx]
    }
    fn mean(&self) -> Duration {
        if self.latencies.is_empty() { return Duration::ZERO; }
        self.latencies.iter().sum::<Duration>() / self.latencies.len() as u32
    }
}

fn create_database(path: &std::path::Path, mode: CryptoMode) -> Database {
    match mode {
        CryptoMode::Plain => Database::create(path).unwrap(),
        CryptoMode::Encrypted => {
            let key = [0x42u8; 32];
            let crypto = Aes256GcmPageCrypto::new(&key, true);
            Database::builder().set_page_crypto(crypto).create(path).unwrap()
        }
    }
}

fn populate_database(db: &Database, num_entries: usize, value_size: usize) {
    let value = vec![0xABu8; value_size];
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(TABLE).unwrap();
        for i in 0..num_entries { table.insert(i as u64, value.as_slice()).unwrap(); }
    }
    write_txn.commit().unwrap();
}

fn benchmark_reads(mode: CryptoMode, num_threads: usize, duration_secs: f64, num_entries: usize, value_size: usize) -> (Duration, LatencyStats, u64) {
    let tmpfile = NamedTempFile::new().unwrap();
    let db = Arc::new(create_database(tmpfile.path(), mode));
    populate_database(&db, num_entries, value_size);

    let barrier = Arc::new(Barrier::new(num_threads + 1));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let total_ops = Arc::new(AtomicU64::new(0));
    let all_latencies = Arc::new(std::sync::Mutex::new(LatencyStats::new()));

    let handles: Vec<_> = (0..num_threads).map(|thread_id| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let stop_flag = Arc::clone(&stop_flag);
        let total_ops = Arc::clone(&total_ops);
        let all_latencies = Arc::clone(&all_latencies);
        thread::spawn(move || {
            let mut local_latencies = LatencyStats::new();
            let mut local_ops = 0u64;
            barrier.wait();
            let mut i = 0usize;
            while !stop_flag.load(Ordering::Relaxed) {
                let key = ((thread_id * 10000 + i) % num_entries) as u64;
                let start = Instant::now();
                let read_txn = db.begin_read().unwrap();
                let table = read_txn.open_table(TABLE).unwrap();
                let _value = table.get(key).unwrap();
                drop(table);
                drop(read_txn);
                local_latencies.record(start.elapsed());
                local_ops += 1;
                i += 1;
            }
            total_ops.fetch_add(local_ops, Ordering::Relaxed);
            all_latencies.lock().unwrap().merge(&local_latencies);
        })
    }).collect();

    let start = Instant::now();
    barrier.wait();
    thread::sleep(Duration::from_secs_f64(duration_secs));
    stop_flag.store(true, Ordering::Relaxed);
    for handle in handles { handle.join().unwrap(); }
    (start.elapsed(), all_latencies.lock().unwrap().clone(), total_ops.load(Ordering::Relaxed))
}

fn benchmark_writes(mode: CryptoMode, num_threads: usize, duration_secs: f64, value_size: usize) -> (Duration, LatencyStats, u64) {
    let tmpfile = NamedTempFile::new().unwrap();
    let db = Arc::new(create_database(tmpfile.path(), mode));

    {
        let write_txn = db.begin_write().unwrap();
        write_txn.open_table(TABLE).unwrap();
        write_txn.commit().unwrap();
    }

    let barrier = Arc::new(Barrier::new(num_threads + 1));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let total_ops = Arc::new(AtomicU64::new(0));
    let all_latencies = Arc::new(std::sync::Mutex::new(LatencyStats::new()));
    let value = vec![0xABu8; value_size];

    let handles: Vec<_> = (0..num_threads).map(|thread_id| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let stop_flag = Arc::clone(&stop_flag);
        let total_ops = Arc::clone(&total_ops);
        let all_latencies = Arc::clone(&all_latencies);
        let value = value.clone();
        thread::spawn(move || {
            let mut local_latencies = LatencyStats::new();
            let mut local_ops = 0u64;
            let mut batch_num = 0usize;
            barrier.wait();
            while !stop_flag.load(Ordering::Relaxed) {
                let base = thread_id * 1_000_000 + batch_num * WRITES_PER_BATCH;
                let start = Instant::now();
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table = write_txn.open_table(TABLE).unwrap();
                    for i in 0..WRITES_PER_BATCH {
                        table.insert((base + i) as u64, value.as_slice()).unwrap();
                    }
                }
                write_txn.commit().unwrap();
                local_latencies.record(start.elapsed());
                local_ops += WRITES_PER_BATCH as u64;
                batch_num += 1;
            }
            total_ops.fetch_add(local_ops, Ordering::Relaxed);
            all_latencies.lock().unwrap().merge(&local_latencies);
        })
    }).collect();

    let start = Instant::now();
    barrier.wait();
    thread::sleep(Duration::from_secs_f64(duration_secs));
    stop_flag.store(true, Ordering::Relaxed);
    for handle in handles { handle.join().unwrap(); }
    (start.elapsed(), all_latencies.lock().unwrap().clone(), total_ops.load(Ordering::Relaxed))
}

fn benchmark_mixed(mode: CryptoMode, num_readers: usize, num_writers: usize, duration_secs: f64, num_entries: usize, value_size: usize) -> (Duration, LatencyStats, LatencyStats, u64, u64) {
    let tmpfile = NamedTempFile::new().unwrap();
    let db = Arc::new(create_database(tmpfile.path(), mode));
    populate_database(&db, num_entries, value_size);

    let barrier = Arc::new(Barrier::new(num_readers + num_writers + 1));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let read_count = Arc::new(AtomicU64::new(0));
    let write_count = Arc::new(AtomicU64::new(0));
    let read_latencies = Arc::new(std::sync::Mutex::new(LatencyStats::new()));
    let write_latencies = Arc::new(std::sync::Mutex::new(LatencyStats::new()));
    let value = vec![0xCDu8; value_size];

    let reader_handles: Vec<_> = (0..num_readers).map(|thread_id| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let stop_flag = Arc::clone(&stop_flag);
        let read_count = Arc::clone(&read_count);
        let read_latencies = Arc::clone(&read_latencies);
        thread::spawn(move || {
            let mut local_latencies = LatencyStats::new();
            let mut local_ops = 0u64;
            barrier.wait();
            let mut i = 0usize;
            while !stop_flag.load(Ordering::Relaxed) {
                let key = ((thread_id * 10000 + i) % num_entries) as u64;
                let start = Instant::now();
                let read_txn = db.begin_read().unwrap();
                let table = read_txn.open_table(TABLE).unwrap();
                let _value = table.get(key).unwrap();
                drop(table);
                drop(read_txn);
                local_latencies.record(start.elapsed());
                local_ops += 1;
                i += 1;
            }
            read_count.fetch_add(local_ops, Ordering::Relaxed);
            read_latencies.lock().unwrap().merge(&local_latencies);
        })
    }).collect();

    let writer_handles: Vec<_> = (0..num_writers).map(|thread_id| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let stop_flag = Arc::clone(&stop_flag);
        let write_count = Arc::clone(&write_count);
        let write_latencies = Arc::clone(&write_latencies);
        let value = value.clone();
        thread::spawn(move || {
            let mut local_latencies = LatencyStats::new();
            let mut local_ops = 0u64;
            let mut batch_num = 0usize;
            barrier.wait();
            while !stop_flag.load(Ordering::Relaxed) {
                let base = num_entries + thread_id * 1_000_000 + batch_num * WRITES_PER_BATCH;
                let start = Instant::now();
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table = write_txn.open_table(TABLE).unwrap();
                    for i in 0..WRITES_PER_BATCH {
                        table.insert((base + i) as u64, value.as_slice()).unwrap();
                    }
                }
                write_txn.commit().unwrap();
                local_latencies.record(start.elapsed());
                local_ops += WRITES_PER_BATCH as u64;
                batch_num += 1;
            }
            write_count.fetch_add(local_ops, Ordering::Relaxed);
            write_latencies.lock().unwrap().merge(&local_latencies);
        })
    }).collect();

    let start = Instant::now();
    barrier.wait();
    thread::sleep(Duration::from_secs_f64(duration_secs));
    stop_flag.store(true, Ordering::Relaxed);
    for handle in reader_handles { handle.join().unwrap(); }
    for handle in writer_handles { handle.join().unwrap(); }
    (start.elapsed(), read_latencies.lock().unwrap().clone(), write_latencies.lock().unwrap().clone(), read_count.load(Ordering::Relaxed), write_count.load(Ordering::Relaxed))
}

fn print_stats(name: &str, stats: &mut LatencyStats, elapsed: Duration, ops: u64) {
    let ops_per_sec = ops as f64 / elapsed.as_secs_f64();
    println!("  {} ({} ops): {:.0} ops/sec", name, ops, ops_per_sec);
    println!("    Latency: mean={:?}, p50={:?}, p99={:?}, p99.9={:?}",
             stats.mean(), stats.percentile(50.0), stats.percentile(99.0), stats.percentile(99.9));
}

fn run_benchmarks_for_mode(mode: CryptoMode, num_entries: usize, value_size: usize, duration: f64) {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  Mode: {:^54} ║", mode.to_string());
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Read scalability
    println!("── Concurrent Reads ──\n");
    for &threads in THREAD_COUNTS {
        let (elapsed, mut latencies, ops) = benchmark_reads(mode, threads, duration, num_entries, value_size);
        print_stats(&format!("{:2} threads", threads), &mut latencies, elapsed, ops);
    }

    // Write scalability
    println!("\n── Concurrent Writes ({} writes/commit) ──\n", WRITES_PER_BATCH);
    for &threads in THREAD_COUNTS {
        let (elapsed, mut latencies, ops) = benchmark_writes(mode, threads, duration, value_size);
        print_stats(&format!("{:2} threads", threads), &mut latencies, elapsed, ops);
    }

    // Mixed workload
    println!("\n── Mixed Workload (8 readers, 2 writers) ──\n");
    let (elapsed, mut read_stats, mut write_stats, total_reads, total_writes) =
        benchmark_mixed(mode, 8, 2, duration, num_entries, value_size);
    println!("  Reads:  {} ({:.0} ops/sec)", total_reads, total_reads as f64 / elapsed.as_secs_f64());
    println!("    Latency: mean={:?}, p50={:?}, p99={:?}, p99.9={:?}",
             read_stats.mean(), read_stats.percentile(50.0), read_stats.percentile(99.0), read_stats.percentile(99.9));
    println!("  Writes: {} ({:.0} ops/sec)", total_writes, total_writes as f64 / elapsed.as_secs_f64());
    println!("    Latency: mean={:?}, p50={:?}, p99={:?}, p99.9={:?}",
             write_stats.mean(), write_stats.percentile(50.0), write_stats.percentile(99.0), write_stats.percentile(99.9));
}

fn main() {
    println!("\n════════════════════════════════════════════════════════════════");
    println!("          redb-turbo Concurrent Benchmark Suite");
    println!("════════════════════════════════════════════════════════════════\n");

    let num_entries = 10_000;
    let value_size = 1024;
    let duration = 2.0;

    println!("Configuration:");
    println!("  • Pre-populated entries: {}", num_entries);
    println!("  • Value size: {} bytes", value_size);
    println!("  • Test duration: {:.1}s per test", duration);
    println!("  • Writes per batch: {}", WRITES_PER_BATCH);
    println!("  • Encryption overhead: {} bytes/page (~0.7%)", 28);

    // Plain mode
    run_benchmarks_for_mode(CryptoMode::Plain, num_entries, value_size, duration);

    // Encrypted mode
    run_benchmarks_for_mode(CryptoMode::Encrypted, num_entries, value_size, duration);

    println!("\n════════════════════════════════════════════════════════════════");
    println!("                     Benchmark Complete!");
    println!("════════════════════════════════════════════════════════════════\n");
}
