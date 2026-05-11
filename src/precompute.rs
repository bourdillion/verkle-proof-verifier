use banderwagon::{Element, Fr};
use sha2::{Digest, Sha256};

/// The Common Reference String for Verkle tree commitments.
/// 256 basis points (one per child in a width-256 node) plus Q for IPA.
pub struct CRS {
    pub basis: Vec<Element>,
    pub q: Element,
}

impl CRS {
    /// Domain width for Ethereum Verkle trees
    pub const DOMAIN_SIZE: usize = 256;

    /// Generate the CRS deterministically from a seed.
    /// In production, these are standardized constants from the Ethereum ceremony.
    pub fn new(seed: &[u8]) -> Self {
        let mut basis = Vec::with_capacity(Self::DOMAIN_SIZE);
        for i in 0..Self::DOMAIN_SIZE {
            let point = hash_to_point(seed, i as u64);
            basis.push(point);
        }
        let q = hash_to_point(seed, Self::DOMAIN_SIZE as u64);
        CRS { basis, q }
    }

    pub fn basis_len(&self) -> usize {
        self.basis.len()
    }
}

/// Hash to a curve point deterministically.
/// Uses try-and-increment: hash the input, interpret as field element,
/// check if it maps to a valid point, increment counter if not.
fn hash_to_point(seed: &[u8], index: u64) -> Element {
    let mut counter: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(index.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        if let Some(point) = Element::from_bytes(&hash) {
            return point;
        }
        counter += 1;
    }
}
