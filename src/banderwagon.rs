use crate::error::VerificationError;
use banderwagon::{Element, Fr};

///  sum of (scalar_i * base_i)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msm_single_element() {
        let g = Element::prime_subgroup_generator();
        let scalar = Fr::from(5u64);
        let result = msm(&[g], &[scalar]).unwrap();
        assert_eq!(result, g * scalar);
    }

    #[test]
    fn msm_two_elements() {
        let g = Element::prime_subgroup_generator();
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let bases = [g * Fr::from(1u64), g * Fr::from(2u64)];
        let result = msm(&bases, &[a, b]).unwrap();
        let expected = bases[0] * a + bases[1] * b;
        assert_eq!(result, expected);
    }

    #[test]
    fn msm_length_mismatch() {
        let g = Element::prime_subgroup_generator();
        let result = msm(&[g, g], &[Fr::from(1u64)]);
        assert!(result.is_err());
    }

    #[test]
    fn inner_product_basic() {
        let a = vec![Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64)];
        let result = inner_product(&a, &b).unwrap();
        // 2*4 + 3*5 = 23
        assert_eq!(result, Fr::from(23u64));
    }

    #[test]
    fn inner_product_length_mismatch() {
        let a = vec![Fr::from(1u64)];
        let b = vec![Fr::from(1u64), Fr::from(2u64)];
        assert!(inner_product(&a, &b).is_err());
    }

    #[test]
    fn inner_product_with_zeros() {
        let a = vec![Fr::from(0u64), Fr::from(5u64)];
        let b = vec![Fr::from(9u64), Fr::from(0u64)];
        let result = inner_product(&a, &b).unwrap();
        assert_eq!(result, Fr::from(0u64));
    }
}
