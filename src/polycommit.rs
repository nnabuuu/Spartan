pub trait PolynomialCommitment {
    type Param;
    type Commitment;
    type Randomness;
    type Proof;
    type EvalCommitment;

    fn commit(
        &self,
        gens: &Self::Param,
        rand: Option<&mut crate::random::RandomTape>,
    ) -> (Self::Commitment, Self::Randomness);

    fn open(
        &self,
        blinds: &Self::Randomness,
        r: &[crate::scalar::Scalar],
        value: &crate::scalar::Scalar,
        blind: Option<&crate::scalar::Scalar>,
        gens: &Self::Param,
        transcript: &mut merlin::Transcript,
        rand: &mut crate::random::RandomTape,
    ) -> (Self::Proof, Self::EvalCommitment);

    fn verify(
        proof: &Self::Proof,
        gens: &Self::Param,
        transcript: &mut merlin::Transcript,
        r: &[crate::scalar::Scalar],
        eval_commit: &Self::EvalCommitment,
        comm: &Self::Commitment,
    ) -> Result<(), crate::errors::ProofVerifyError>;
}
