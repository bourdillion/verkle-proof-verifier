use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("invalid proof length: expected {expected}, got {got}")]
    InvalidProofLength { expected: usize, got: usize },

    #[error("commitment mismatch at index {0}")]
    CommitmentMismatch(usize),

    #[error("IPA verification failed")]
    IpaCheckFailed,

    #[error("multiproof verification failed")]
    MultiproofFailed,

    #[error("deserialization failed: {0}")]
    DeserializationError(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}
