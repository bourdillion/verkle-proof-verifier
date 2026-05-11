use banderwagon::{Element, Fr};

/// Single Verkle tree commitment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerkleCommitment(pub Element);

/// Inner Product Argument proof.
#[derive(Debug, Clone)]
pub struct IpaProof {
    pub l: Vec<Element>,
    pub r: Vec<Element>,
    pub a: Fr,
}

/// Multipoint proof that batches multiple openings into one IPA.
#[derive(Debug, Clone)]
pub struct MultiPointProof {
    /// Helper polynomial commitment
    pub d: Element,
    /// The underlying IPA proof
    pub ipa: IpaProof,
}

/// TVerkle proof as it appears in a block.
#[derive(Debug, Clone)]
pub struct VerkleProof {
    /// Multipoint opening proof
    pub multi_point: MultiPointProof,
    /// Internal node commitments along the proven paths
    pub commitments: Vec<VerkleCommitment>,
}

impl VerkleCommitment {
    pub fn inner(&self) -> &Element {
        &self.0
    }
}

impl From<Element> for VerkleCommitment {
    fn from(e: Element) -> Self {
        VerkleCommitment(e)
    }
}
