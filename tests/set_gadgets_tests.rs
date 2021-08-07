// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate dusk_plonk;
extern crate plonk_gadgets;

use dusk_plonk::prelude::*;
use plonk_gadgets::{Error as GadgetError, SetGadgets::*};

#[test]
fn test_set_non_membership_gadget() -> Result<(), Error> {
    // The circuit closure runs the set_non_membership gadget, which constraints the value to
    // not be part of the set.
    let circuit =
        |composer: &mut StandardComposer,
         set: Vec<BlsScalar>,
         value: BlsScalar|
         -> Result<(), GadgetError> { set_non_membership_gadget(composer, set, value) };

    // Generate Composer & Public Parameters
    let pub_params = PublicParameters::setup(1 << 8, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 7)?;
    let set = vec![BlsScalar::from(1), BlsScalar::from(2)];
    let different_set = vec![BlsScalar::from(3), BlsScalar::from(4)];

    // Value is part of the set, prover shouldn't be able to construct an incorrect circuit
    let mut prover = Prover::new(b"testing");
    assert!(circuit(prover.mut_cs(), set.clone(), set[0].clone()).is_err());

    // Prover and verifier using different sets should fail
    // Prover constructs a correct circuit
    let mut prover = Prover::new(b"testing");
    assert!(circuit(prover.mut_cs(), set.clone(), BlsScalar::from(5)).is_ok());

    let pi = prover.mut_cs().construct_dense_pi_vec().clone();
    prover.preprocess(&ck)?;
    let proof = prover.prove(&ck)?;

    // Verification
    let mut verifier = Verifier::new(b"testing");
    // verifier can construct a correct circuit
    assert!(circuit(verifier.mut_cs(), different_set.clone(), BlsScalar::zero()).is_ok());
    verifier.preprocess(&ck)?;
    // But his set corresponds to a different set than prover's, so the proof won't be correct
    assert!(verifier.verify(&proof, &vk, &pi).is_err());

    // Both prover and verifier using the same circuit. This should pass.
    let mut verifier = Verifier::new(b"testing");
    assert!(circuit(verifier.mut_cs(), set.clone(), BlsScalar::zero()).is_ok());
    verifier.preprocess(&ck)?;
    assert!(verifier.verify(&proof, &vk, &pi).is_ok());

    Ok(())
}

#[test]
fn test_vector_sum_gadget() -> Result<(), Error> {
    // Generate Composer & Public Parameters
    let pub_params = PublicParameters::setup(1 << 8, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 7)?;
    struct TestCase {
        vector: Vec<BlsScalar>,
        sum: BlsScalar,
        expected: bool,
    }
    let test_cases = vec![
        TestCase {
            vector: vec![1, 0, 0, 0]
                .iter()
                .map(|x| BlsScalar::from(*x))
                .collect(),
            sum: BlsScalar::one(),
            expected: true,
        },
        TestCase {
            vector: vec![1, 2, 3, 4]
                .iter()
                .map(|x| BlsScalar::from(*x))
                .collect(),
            sum: BlsScalar::from(10),
            expected: true,
        },
        TestCase {
            vector: vec![1, 2, 3, 4]
                .iter()
                .map(|x| BlsScalar::from(*x))
                .collect(),
            sum: BlsScalar::from(12),
            expected: false,
        },
    ];

    for case in test_cases.into_iter() {
        let mut prover = Prover::default();

        assert!(vector_sum_gadget(prover.mut_cs(), &case.vector, case.sum).is_ok());
        let pi = prover.mut_cs().construct_dense_pi_vec().clone();
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        let mut verifier = Verifier::default();
        assert!(vector_sum_gadget(verifier.mut_cs(), &case.vector, BlsScalar::zero()).is_ok());
        verifier.preprocess(&ck)?;
        if case.expected {
            assert!(verifier.verify(&proof, &vk, &pi).is_ok());
        } else {
            assert!(verifier.verify(&proof, &vk, &pi).is_err());
        }
    }
    Ok(())
}
