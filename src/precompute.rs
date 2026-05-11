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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crs_has_correct_size() {
        let crs = CRS::new(b"test_seed");
        assert_eq!(crs.basis.len(), CRS::DOMAIN_SIZE);
    }

    #[test]
    fn crs_is_deterministic() {
        let crs1 = CRS::new(b"same_seed");
        let crs2 = CRS::new(b"same_seed");
        for (a, b) in crs1.basis.iter().zip(crs2.basis.iter()) {
            assert_eq!(a, b);
        }
        assert_eq!(crs1.q, crs2.q);
    }

    #[test]
    fn different_seeds_different_crs() {
        let crs1 = CRS::new(b"seed_a");
        let crs2 = CRS::new(b"seed_b");
        assert_ne!(crs1.basis[0], crs2.basis[0]);
    }

    #[test]
    fn basis_points_are_distinct() {
        let crs = CRS::new(b"test_seed");
        for i in 0..crs.basis.len() {
            for j in (i + 1)..crs.basis.len() {
                assert_ne!(crs.basis[i], crs.basis[j]);
            }
        }
    }

    #[test]
    fn q_is_distinct_from_basis() {
        let crs = CRS::new(b"test_seed");
        for point in &crs.basis {
            assert_ne!(*point, crs.q);
        }
    }
}
