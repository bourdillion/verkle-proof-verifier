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
