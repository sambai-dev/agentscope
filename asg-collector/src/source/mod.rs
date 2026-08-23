//! Event source backends.

#[cfg(target_os = "linux")]
pub mod linux;
pub mod sim;
