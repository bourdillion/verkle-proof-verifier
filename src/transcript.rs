// src/transcript.rs
//
// Fiat-Shamir transcript for non-interactive proof verification.

use ark_ff::PrimeField;
use banderwagon::CanonicalSerialize;
use banderwagon::Fr;
use sha2::{Digest, Sha256};

/// A Fiat-Shamir transcript that produces deterministic
/// challenges from absorbed proof elements.
pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript with a domain label.
    pub fn new(label: &[u8]) -> Self {
        let mut t = Transcript { state: Vec::new() };
        t.append_bytes(label);
        t
    }

    /// Domain separation. Absorbs a label into the transcript
    pub fn domain_sep(&mut self, label: &[u8]) {
        self.append_bytes(label);
    }

    /// Absorb raw bytes into the transcript state.
    fn append_bytes(&mut self, data: &[u8]) {
        self.state.extend_from_slice(data);
    }

    /// Absorb an elliptic curve point
    pub fn append_point(&mut self, point: &banderwagon::Element, label: &[u8]) {
        self.append_bytes(label);
        let mut buf = Vec::new();
        point
            .serialize_compressed(&mut buf)
            .expect("point serialization should not fail");
        self.append_bytes(&buf);
    }

    /// Absorb a scalar field element into the transcript.
    pub fn append_scalar(&mut self, scalar: &Fr, label: &[u8]) {
        self.append_bytes(label);
        let mut buf = Vec::new();
        scalar
            .serialize_compressed(&mut buf)
            .expect("scalar serialization should not fail");
        self.append_bytes(&buf);
    }

    /// Squeeze a challenge scalar from the transcript.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Fr {
        self.append_bytes(label);

        let mut hasher = Sha256::new();
        hasher.update(&self.state);
        let hash_output = hasher.finalize();

        // Reset state to hash output for chaining
        self.state = hash_output.to_vec();

        // Reduce hash output to a field element
        Fr::from_be_bytes_mod_order(&hash_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_challenge() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.append_bytes(b"hello");
        t2.append_bytes(b"hello");

        let c1 = t1.challenge_scalar(b"challenge");
        let c2 = t2.challenge_scalar(b"challenge");
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_labels_different_challenges() {
        let mut t1 = Transcript::new(b"proto_a");
        let mut t2 = Transcript::new(b"proto_b");

        let c1 = t1.challenge_scalar(b"x");
        let c2 = t2.challenge_scalar(b"x");
        assert_ne!(c1, c2);
    }

    #[test]
    fn order_matters() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.append_bytes(b"first");
        t1.append_bytes(b"second");

        t2.append_bytes(b"second");
        t2.append_bytes(b"first");

        let c1 = t1.challenge_scalar(b"x");
        let c2 = t2.challenge_scalar(b"x");
        assert_ne!(c1, c2);
    }

    #[test]
    fn chained_challenges_differ() {
        let mut t = Transcript::new(b"test");
        let c1 = t.challenge_scalar(b"first");
        let c2 = t.challenge_scalar(b"second");
        assert_ne!(c1, c2);
    }

    #[test]
    fn challenge_is_nonzero() {
        let mut t = Transcript::new(b"test");
        let c = t.challenge_scalar(b"x");
        assert_ne!(c, Fr::from(0u64));
    }
}
