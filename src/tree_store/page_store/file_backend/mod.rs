// Standard Unix backend (used directly on non-Linux Unix, or as fallback on Linux)
#[cfg(any(unix, target_os = "wasi"))]
mod unix;

// io_uring backend wrapper for Linux (with runtime fallback to standard)
#[cfg(target_os = "linux")]
mod io_uring_backend;

// On Linux, use the io_uring wrapper which handles runtime detection
#[cfg(target_os = "linux")]
pub use io_uring_backend::FileBackend;

// On non-Linux Unix (macOS, BSD, etc.), use standard backend directly
#[cfg(all(any(unix, target_os = "wasi"), not(target_os = "linux")))]
pub use unix::FileBackend;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::FileBackend;

#[cfg(not(any(windows, unix, target_os = "wasi")))]
mod fallback;
#[cfg(not(any(windows, unix, target_os = "wasi")))]
pub use fallback::FileBackend;
