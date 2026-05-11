use crate::error::VerificationError;
use banderwagon::{Element, Fr};

/// Multi-scalar multiplication: sum of (scalar_i * base_i)
pub fn msm(bases: &[Element], scalars: &[Fr]) -> Result<Element, VerificationError> {
    if bases.len() != scalars.len() {
        return Err(VerificationError::InvalidInput(format!(
            "msm length mismatch: {} bases, {} scalars",
            bases.len(),
            scalars.len()
        )));
    }
    Ok(banderwagon::multi_scalar_mul(bases, scalars))
}

/// Compute the inner product of two scalar vectors: sum of (a_i * b_i)
pub fn inner_product(a: &[Fr], b: &[Fr]) -> Result<Fr, VerificationError> {
    if a.len() != b.len() {
        return Err(VerificationError::InvalidInput(format!(
            "inner product length mismatch: {} vs {}",
            a.len(),
            b.len()
        )));
    }
    let mut result = Fr::from(0u64);
    for (ai, bi) in a.iter().zip(b.iter()) {
        result += *ai * *bi;
    }
    Ok(result)
}
