use crate::error::VerificationError;
use crate::precompute::CRS;
use crate::proof::IpaProof;
use crate::transcript::Transcript;
use ark_ff::Field;
use banderwagon::{Element, Fr};

/// Verify an IPA proof that polynomial committed in C evaluates to y at z.
///
/// The verifier checks the recursive halving proof without
/// ever seeing the full polynomial.
pub fn verify_ipa(
    transcript: &mut Transcript,
    crs: &CRS,
    commitment: Element,
    proof: &IpaProof,
    eval_point: Fr,
    eval_value: Fr,
) -> Result<bool, VerificationError> {
    let n = crs.basis_len();
    let k = proof.l.len();

    // k rounds of halving means we started with 2^k elements
    if proof.r.len() != k {
        return Err(VerificationError::InvalidProofLength {
            expected: k,
            got: proof.r.len(),
        });
    }
    if (1 << k) != n {
        return Err(VerificationError::InvalidInput(format!(
            "proof depth {} does not match domain size {}",
            k, n
        )));
    }

    // Generate challenges from the transcript
    let mut challenges = Vec::with_capacity(k);
    let mut challenges_inv = Vec::with_capacity(k);

    for i in 0..k {
        transcript.append_point(&proof.l[i], b"L");
        transcript.append_point(&proof.r[i], b"R");
        let x = transcript.challenge_scalar(b"x");
        let x_inv = x.inverse().ok_or(VerificationError::InvalidInput(
            "challenge has no inverse".into(),
        ))?;
        challenges.push(x);
        challenges_inv.push(x_inv);
    }

    // Fold the commitment: C' = C + sum(x_i^2 * L_i) + sum(x_inv_i^2 * R_i)
    let mut c_prime = commitment;
    for i in 0..k {
        let x_sq = challenges[i].square();
        let x_inv_sq = challenges_inv[i].square();
        c_prime = c_prime + proof.l[i] * x_sq + proof.r[i] * x_inv_sq;
    }

    // Fold the generators using challenges to get a single generator
    let g_final = fold_generators(&crs.basis, &challenges)?;

    // Fold the evaluation point powers using challenges
    let b_final = fold_scalars(eval_point, &challenges, n)?;

    // Check: C' == a * g_final + (a * b_final) * Q
    // where a*b_final accounts for the inner product evaluation
    let lhs = c_prime;
    let rhs = g_final * proof.a + crs.q * (proof.a * b_final - eval_value);

    Ok(lhs == rhs)
}

/// Fold n generators down to 1 using the challenge sequence.
/// At each round, pairs are combined: g_left * x_inv + g_right * x
fn fold_generators(
    generators: &[Element],
    challenges: &[Fr],
) -> Result<Element, VerificationError> {
    let mut gens = generators.to_vec();

    for x_inv in challenges
        .iter()
        .rev()
        .map(|x| x.inverse().expect("challenge invertible"))
    {
        let half = gens.len() / 2;
        let mut folded = Vec::with_capacity(half);
        for j in 0..half {
            folded.push(gens[j] * x_inv + gens[half + j] * (x_inv.inverse().unwrap()));
        }
        gens = folded;
    }

    Ok(gens[0])
}

/// Fold the evaluation basis (powers of z) using challenges.
fn fold_scalars(eval_point: Fr, challenges: &[Fr], n: usize) -> Result<Fr, VerificationError> {
    // Build the powers: [1, z, z^2, ..., z^(n-1)]
    let mut powers = Vec::with_capacity(n);
    let mut current = Fr::from(1u64);
    for _ in 0..n {
        powers.push(current);
        current *= eval_point;
    }

    // Fold using the same challenge pattern as generators
    let mut scalars = powers;
    for x_inv in challenges
        .iter()
        .rev()
        .map(|x| x.inverse().expect("challenge invertible"))
    {
        let half = scalars.len() / 2;
        let mut folded = Vec::with_capacity(half);
        for j in 0..half {
            folded.push(scalars[j] * x_inv + scalars[half + j] * (x_inv.inverse().unwrap()));
        }
        scalars = folded;
    }

    Ok(scalars[0])
}
