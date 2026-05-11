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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_single_value() {
        let crs = CRS::new(b"test");
        let values = vec![Fr::from(7u64)];
        let result = pedersen_commit(&crs, &values);
        assert!(result.is_ok());
    }

    #[test]
    fn commit_full_width() {
        let crs = CRS::new(b"test");
        let values: Vec<Fr> = (0..256).map(|i| Fr::from(i as u64)).collect();
        let result = pedersen_commit(&crs, &values);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_too_many_values() {
        let crs = CRS::new(b"test");
        let values = vec![Fr::from(1u64); 257];
        assert!(pedersen_commit(&crs, &values).is_err());
    }

    #[test]
    fn commitment_is_deterministic() {
        let crs = CRS::new(b"test");
        let values = vec![Fr::from(3u64), Fr::from(5u64)];
        let c1 = pedersen_commit(&crs, &values).unwrap();
        let c2 = pedersen_commit(&crs, &values).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_values_different_commitments() {
        let crs = CRS::new(b"test");
        let c1 = pedersen_commit(&crs, &[Fr::from(1u64)]).unwrap();
        let c2 = pedersen_commit(&crs, &[Fr::from(2u64)]).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn verify_commitment_roundtrip() {
        let crs = CRS::new(b"test");
        let values = vec![Fr::from(10u64), Fr::from(20u64)];
        let commitment = pedersen_commit(&crs, &values).unwrap();
        assert!(verify_commitment(&crs, &commitment, &values).unwrap());
    }

    #[test]
    fn verify_commitment_rejects_wrong_values() {
        let crs = CRS::new(b"test");
        let values = vec![Fr::from(10u64), Fr::from(20u64)];
        let commitment = pedersen_commit(&crs, &values).unwrap();
        let wrong = vec![Fr::from(10u64), Fr::from(99u64)];
        assert!(!verify_commitment(&crs, &commitment, &wrong).unwrap());
    }
}
