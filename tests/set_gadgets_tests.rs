// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate dusk_plonk;
extern crate plonk_gadgets;

use dusk_plonk::prelude::*;
use plonk_gadgets::{AllocatedScalar, Error as GadgetError, SetGadgets::*};

#[test]
fn test_set_non_membership() -> Result<(), Error> {
    // The circuit closure runs the is_not_zero fn and constraints the input to
    // not be zero.
    let circuit = |composer: &mut StandardComposer,
                   set: Vec<BlsScalar>,
                   value: BlsScalar|
     -> Result<(), GadgetError> { set_non_membership(composer, set, value) };

    // Generate Composer & Public Parameters
    let pub_params = PublicParameters::setup(1 << 8, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 7)?;
    let set = vec![BlsScalar::from(1), BlsScalar::from(2)];
    let different_set = vec![BlsScalar::from(3), BlsScalar::from(4)];

    // Value is part of the set, shouldn't be able to construct a circuit
    let mut prover = Prover::new(b"testing");
    assert!(circuit(prover.mut_cs(), set.clone(), BlsScalar::from(2)).is_err());
    // prover.clear_witness();

    // Prover and verifier using different sets should fail
    // Prover constructs a correct circuit
    let mut prover = Prover::new(b"testing");
    assert!(circuit(prover.mut_cs(), different_set.clone(), BlsScalar::from(5)).is_ok());

    let mut pi = prover.mut_cs().construct_dense_pi_vec().clone();
    // let mut pi: Vec<PublicInputValue> = set.into_iter().map(|x| x.into()).collect();
    prover.preprocess(&ck)?;
    let proof = prover.prove(&ck)?;

    // Verification
    let mut verifier = Verifier::new(b"testing");
    // verifier can construct a correct circuit
    assert!(circuit(verifier.mut_cs(), set.clone(), BlsScalar::zero()).is_ok());
    verifier.preprocess(&ck)?;
    assert!(verifier.verify(&proof, &vk, &pi).is_err());

    // Value & value assigned set correctly. This should pass.
    // Proving
    let mut prover = Prover::new(b"testing");
    circuit(prover.mut_cs(), set.clone(), BlsScalar::from(7))
        .map_err(|_| Error::BlsScalarMalformed)?;
    pi = prover.mut_cs().construct_dense_pi_vec().clone();
    let proof = prover.prove(&ck)?;

    let mut verifier = Verifier::new(b"testing");
    assert!(circuit(verifier.mut_cs(), set.clone(), BlsScalar::zero()).is_ok());
    verifier.preprocess(&ck)?;
    assert!(verifier.verify(&proof, &vk, &pi).is_ok());
    // assert!(verifier.verify(&proof, &vk, &vec![BlsScalar::zero()]).is_ok());

    Ok(())
}
