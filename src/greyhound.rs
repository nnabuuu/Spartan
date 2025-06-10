#![cfg(feature = "greyhound")]

use crate::dense_mlpoly::DensePolynomial;
use crate::polycommit::PolynomialCommitment;
use crate::random::RandomTape;
use crate::scalar::Scalar;
use crate::errors::ProofVerifyError;
use merlin::Transcript;
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GreyhoundCommitment(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GreyhoundBlinds {
    pub poly: Vec<Scalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GreyhoundEvalCommitment(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GreyhoundEvalProof {
    point: Vec<Scalar>,
    value: Scalar,
    poly: Vec<Scalar>,
}

use crate::nizk::DotProductProofGens;

pub struct GreyhoundGens {
    pub gens: DotProductProofGens,
}

fn hash_scalars(data: &[Scalar]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for s in data {
        hasher.update(s.to_bytes());
    }
    hasher.finalize().into()
}

#[cfg(feature = "greyhound")]
impl PolynomialCommitment for DensePolynomial {
    type Param = GreyhoundGens;
    type Commitment = GreyhoundCommitment;
    type Randomness = GreyhoundBlinds;
    type Proof = GreyhoundEvalProof;
    type EvalCommitment = GreyhoundEvalCommitment;

    fn commit(
        &self,
        _gens: &Self::Param,
        _rand: Option<&mut RandomTape>,
    ) -> (Self::Commitment, Self::Randomness) {
        let bytes = hash_scalars(self.values());
        (
            GreyhoundCommitment(bytes),
            GreyhoundBlinds { poly: self.values().to_vec() },
        )
    }

    fn open(
        &self,
        blinds: &Self::Randomness,
        r: &[Scalar],
        _value: &Scalar,
        _blind: Option<&Scalar>,
        _gens: &Self::Param,
        _transcript: &mut Transcript,
        _rand: &mut RandomTape,
    ) -> (Self::Proof, Self::EvalCommitment) {
        let val = self.evaluate(r);
        (
            GreyhoundEvalProof {
                point: r.to_vec(),
                value: val,
                poly: blinds.poly.clone(),
            },
            GreyhoundEvalCommitment(hash_scalars(&[val])),
        )
    }

    fn verify(
        proof: &Self::Proof,
        _gens: &Self::Param,
        _transcript: &mut Transcript,
        r: &[Scalar],
        _eval_commit: &Self::EvalCommitment,
        comm: &Self::Commitment,
    ) -> Result<(), ProofVerifyError> {
        if proof.point != r {
            return Err(ProofVerifyError::InternalError);
        }
        let expected_comm = GreyhoundCommitment(hash_scalars(&proof.poly));
        if &expected_comm != comm {
            return Err(ProofVerifyError::InternalError);
        }
        let poly = DensePolynomial::new(proof.poly.clone());
        if poly.evaluate(r) != proof.value {
            return Err(ProofVerifyError::InternalError);
        }
        Ok(())
    }
}

impl GreyhoundGens {
    pub fn new() -> Self {
        GreyhoundGens {
            gens: DotProductProofGens::new(1, b"greyhound"),
        }
    }
}

pub fn encode_polynomial(poly: &DensePolynomial) -> Vec<Scalar> {
    poly.values().to_vec()
}

pub fn add_hiding_noise(poly: &mut Vec<Scalar>, tape: &mut RandomTape) {
    for p in poly.iter_mut() {
        *p += tape.random_scalar(b"greyhound_noise");
    }
}

pub fn produce_evaluation_proof(poly: &DensePolynomial, r: &[Scalar]) -> (GreyhoundEvalProof, GreyhoundEvalCommitment) {
    let val = poly.evaluate(r);
    (
        GreyhoundEvalProof { point: r.to_vec(), value: val, poly: poly.values().to_vec() },
        GreyhoundEvalCommitment(hash_scalars(&[val])),
    )
}
