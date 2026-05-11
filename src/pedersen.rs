use crate::error::VerificationError;
use crate::precompute::CRS;
use banderwagon::{Element, Fr};

/// Compute a Pedersen commitment over a vector of scalars using the CRS.
/// C = sum of (value_i * basis_i)
pub fn pedersen_commit(crs: &CRS, values: &[Fr]) -> Result<Element, VerificationError> {
    if values.len() > crs.basis_len() {
        return Err(VerificationError::InvalidInput(format!(
            "too many values for commitment: {} values, {} basis points",
            values.len(),
            crs.basis_len()
        )));
    }
    crate::banderwagon::msm(&crs.basis[..values.len()], values)
}

/// Verify that a commitment matches the given values.
pub fn verify_commitment(
    crs: &CRS,
    commitment: &Element,
    values: &[Fr],
) -> Result<bool, VerificationError> {
    let recomputed = pedersen_commit(crs, values)?;
    Ok(recomputed == *commitment)
}
