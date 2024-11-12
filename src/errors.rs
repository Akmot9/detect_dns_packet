use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsPacketError {
    #[error("Insufficient data: expected at least {expected} bytes, but got {actual}")]
    InsufficientData { expected: usize, actual: usize },
}