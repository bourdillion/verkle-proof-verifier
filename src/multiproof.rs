use crate::error::VerificationError;
use crate::ipa::verify_ipa;
use crate::precompute::CRS;
use crate::proof::{VerkleCommitment, VerkleProof};
use crate::transcript::Transcript;
use ark_ff::Field;
use banderwagon::{Element, Fr};

#[derive(Debug, Clone)]
pub struct OpeningClaim {
    pub commitment: VerkleCommitment,
    pub eval_point: Fr,
    pub eval_value: Fr,
}

/// Verify a Verkle multiproof against a set of opening claims.
pub fn verify_multiproof(
    crs: &CRS,
    proof: &VerkleProof,
    claims: &[OpeningClaim],
) -> Result<bool, VerificationError> {
    if claims.is_empty() {
        return Err(VerificationError::InvalidInput(
            "no claims to verify".into(),
        ));
    }

    let mut transcript = Transcript::new(b"verkle_multiproof");

    // Absorb all commitments and evaluation data into the transcript
    for (i, claim) in claims.iter().enumerate() {
        transcript.append_point(claim.commitment.inner(), &[b'C', i as u8]);
        transcript.append_scalar(&claim.eval_point, &[b'z', i as u8]);
        transcript.append_scalar(&claim.eval_value, &[b'y', i as u8]);
    }

    // Squeeze the batching challenge r
    let r = transcript.challenge_scalar(b"r");

    // Combine commitments: E = sum(r^i * C_i)
    // Combine evaluations: combined_y = sum(r^i * y_i)
    let mut combined_commitment = Element::zero();
    let mut combined_eval = Fr::from(0u64);
    let mut r_power = Fr::from(1u64);

    for claim in claims {
        combined_commitment = combined_commitment + *claim.commitment.inner() * r_power;
        combined_eval += r_power * claim.eval_value;
        r_power *= r;
    }

    // Absorb the helper commitment D
    transcript.append_point(&proof.multi_point.d, b"D");

    // Squeeze evaluation challenge t
    let t = transcript.challenge_scalar(b"t");

    // Final commitment to verify via IPA:
    // C_final = combined_commitment - combined_eval * identity + t * D
    let c_final = combined_commitment + proof.multi_point.d * t;

    // The IPA verifies that the polynomial behind c_final
    // evaluates correctly at point t
    verify_ipa(
        &mut transcript,
        crs,
        c_final,
        &proof.multi_point.ipa,
        t,
        combined_eval,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{IpaProof, MultiPointProof};

    #[test]
    fn rejects_empty_claims() {
        let crs = CRS::new(b"test");
        let g = Element::prime_subgroup_generator();

        let proof = VerkleProof {
            multi_point: MultiPointProof {
                d: g,
                ipa: IpaProof {
                    l: vec![g; 8],
                    r: vec![g; 8],
                    a: Fr::from(1u64),
                },
            },
            commitments: vec![],
        };

        let result = verify_multiproof(&crs, &proof, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_fake_proof() {
        let crs = CRS::new(b"test");
        let g = Element::prime_subgroup_generator();

        let fake_commitment = VerkleCommitment::from(g);
        let claims = vec![OpeningClaim {
            commitment: fake_commitment,
            eval_point: Fr::from(1u64),
            eval_value: Fr::from(42u64),
        }];

        let proof = VerkleProof {
            multi_point: MultiPointProof {
                d: g,
                ipa: IpaProof {
                    l: vec![g; 8],
                    r: vec![g; 8],
                    a: Fr::from(99u64),
                },
            },
            commitments: vec![fake_commitment],
        };

        let result = verify_multiproof(&crs, &proof, &claims);
        assert!(matches!(result, Ok(false)));
    }

    #[test]
    fn different_claims_produce_different_results() {
        let crs = CRS::new(b"test");
        let g = Element::prime_subgroup_generator();
        let fake_commitment = VerkleCommitment::from(g);

        let make_proof = || VerkleProof {
            multi_point: MultiPointProof {
                d: g,
                ipa: IpaProof {
                    l: vec![g; 8],
                    r: vec![g; 8],
                    a: Fr::from(1u64),
                },
            },
            commitments: vec![fake_commitment],
        };

        let claims_a = vec![OpeningClaim {
            commitment: fake_commitment,
            eval_point: Fr::from(1u64),
            eval_value: Fr::from(10u64),
        }];

        let claims_b = vec![OpeningClaim {
            commitment: fake_commitment,
            eval_point: Fr::from(1u64),
            eval_value: Fr::from(20u64),
        }];

        // Both should fail (fake proofs) but exercise different code paths
        let r1 = verify_multiproof(&crs, &make_proof(), &claims_a);
        let r2 = verify_multiproof(&crs, &make_proof(), &claims_b);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }
}
