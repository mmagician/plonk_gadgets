// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate dusk_plonk;
extern crate plonk_gadgets;

use dusk_plonk::prelude::*;
use plonk_gadgets::AllocatedScalar;
use plonk_gadgets::{Error as GadgetError, SetGadgets::*};

#[test]
fn test_vector_non_membership_gadget() -> Result<(), Error> {
    // The circuit closure runs the set_non_membership gadget, which constraints the witness to
    // not be part of the vector.
    let circuit = |composer: &mut StandardComposer,
                   vector: &Vec<BlsScalar>,
                   witness: BlsScalar|
     -> Result<(), GadgetError> {
        let v = AllocatedScalar::allocate(composer, witness);
        vector_non_membership_gadget(composer, &vector, v)
    };

    // Generate Composer & Public Parameters
    let pub_params = PublicParameters::setup(1 << 8, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 7)?;
    struct TestCase {
        prover_vector: Vec<BlsScalar>,
        verifier_vector: Vec<BlsScalar>,
        witness: BlsScalar,
        expected_witness: bool,
        expected_prover: bool,
        desc: String,
    }

    let test_cases: Vec<TestCase> = vec![
        TestCase {
            prover_vector: vec![BlsScalar::from(3), BlsScalar::from(4)],
            verifier_vector: vec![BlsScalar::from(3), BlsScalar::from(4)],
            witness: BlsScalar::from(5),
            desc: String::from("Element not part of the vector, should pass"),
            expected_witness: true,
            expected_prover: true,
        },
        TestCase {
            prover_vector: vec![BlsScalar::from(3), BlsScalar::from(4)],
            verifier_vector: vec![BlsScalar::from(3), BlsScalar::from(4)],
            witness: BlsScalar::from(3),
            desc: String::from("Element part of vector, prover shouldnt construct a valid proof"),
            expected_witness: false,
            expected_prover: false,
        },
        TestCase {
            prover_vector: vec![BlsScalar::from(3), BlsScalar::from(3), BlsScalar::from(5)],
            verifier_vector: vec![BlsScalar::from(3), BlsScalar::from(3), BlsScalar::from(5)],
            witness: BlsScalar::from(4),
            desc: String::from(
                "Duplicate elements in the vector, shouldn't matter for neither of the parties",
            ),
            expected_witness: true,
            expected_prover: true,
        },
        TestCase {
            prover_vector: vec![BlsScalar::from(3)],
            verifier_vector: vec![BlsScalar::from(3), BlsScalar::from(4), BlsScalar::from(5)],
            witness: BlsScalar::from(6),
            desc: String::from(
                "Verifier vector has different lenght, shouldn't accept trivial proof",
            ),
            expected_witness: false,
            expected_prover: true,
        },
        TestCase {
            prover_vector: vec![BlsScalar::from(3), BlsScalar::from(4)],
            verifier_vector: vec![BlsScalar::from(5), BlsScalar::from(6)],
            witness: BlsScalar::from(7),
            desc: String::from("Prover and verifier vectors same length, different elements"),
            expected_witness: false,
            expected_prover: true,
        },
    ];

    for case in test_cases.iter() {
        println!("{}", case.desc);

        let mut prover = Prover::new(b"testing");
        if case.expected_prover {
            assert!(circuit(prover.mut_cs(), &case.prover_vector, case.witness).is_ok());
        } else {
            assert!(circuit(prover.mut_cs(), &case.prover_vector, case.witness).is_err());
            continue;
        }
        let pi = prover.mut_cs().construct_dense_pi_vec().clone();
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        let mut verifier = Verifier::new(b"testing");
        assert!(circuit(verifier.mut_cs(), &case.verifier_vector, BlsScalar::zero()).is_ok());
        verifier.preprocess(&ck)?;
        if case.expected_witness {
            assert!(verifier.verify(&proof, &vk, &pi).is_ok());
        } else {
            assert!(verifier.verify(&proof, &vk, &pi).is_err());
        }
    }

    Ok(())
}

#[test]
fn test_vector_sum_gadget() -> Result<(), Error> {
    // Generate Composer & Public Parameters
    let pub_params = PublicParameters::setup(1 << 8, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 7)?;
    struct TestCase {
        vector: Vec<BlsScalar>,
        sum: u64,
        expected: bool,
    }
    let test_cases = vec![
        TestCase {
            vector: vec![1, 0, 0, 0]
                .iter()
                .map(|x| BlsScalar::from(*x))
                .collect(),
            sum: 1,
            expected: true,
        },
        TestCase {
            vector: vec![1, 2, 3, 4]
                .iter()
                .map(|x| BlsScalar::from(*x))
                .collect(),
            sum: 10,
            expected: true,
        },
        TestCase {
            vector: vec![0, 0, 0, 0]
                .iter()
                .map(|x| BlsScalar::from(*x))
                .collect(),
            sum: 0,
            expected: true,
        },
        TestCase {
            vector: vec![1, 2, 3, 4]
                .iter()
                .map(|x| BlsScalar::from(*x))
                .collect(),
            sum: 12,
            expected: false,
        },
    ];

    for case in test_cases.into_iter() {
        let mut prover = Prover::default();

        let allocated_vector: Vec<AllocatedScalar> = case
            .vector
            .iter()
            .map(|x| AllocatedScalar::allocate(prover.mut_cs(), *x))
            .collect();
        assert!(vector_sum_gadget(prover.mut_cs(), &allocated_vector, case.sum).is_ok());
        let pi = prover.mut_cs().construct_dense_pi_vec().clone();
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        let mut verifier = Verifier::default();
        let allocated_vector: Vec<AllocatedScalar> = case
            .vector
            .iter()
            .map(|x| AllocatedScalar::allocate(verifier.mut_cs(), *x))
            .collect();

        assert!(vector_sum_gadget(verifier.mut_cs(), &allocated_vector, 0).is_ok());
        verifier.preprocess(&ck)?;
        if case.expected {
            assert!(verifier.verify(&proof, &vk, &pi).is_ok());
        } else {
            assert!(verifier.verify(&proof, &vk, &pi).is_err());
        }
    }
    Ok(())
}

#[test]
fn test_set_membership_gadget() -> Result<(), Error> {
    // The circuit closure runs the set_membership gadget, which constraints the value to
    // be part of the set.
    let circuit = |composer: &mut StandardComposer,
                   set: &Vec<BlsScalar>,
                   value: BlsScalar|
     -> Result<(), GadgetError> {
        let assigned_value = AllocatedScalar::allocate(composer, value);
        set_membership_gadget(composer, set, assigned_value)
    };

    // Generate Composer & Public Parameters
    let pub_params = PublicParameters::setup(1 << 8, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 7)?;

    struct TestCase {
        prover_set: Vec<BlsScalar>,
        verifier_set: Vec<BlsScalar>,
        value: BlsScalar,
        expected: bool,
        desc: String,
    }

    let test_cases: Vec<TestCase> = vec![
        TestCase {
            prover_set: vec![BlsScalar::from(3), BlsScalar::from(4)],
            verifier_set: vec![BlsScalar::from(3), BlsScalar::from(4)],
            value: BlsScalar::from(3),
            desc: String::from("Element part of the set, should pass"),
            expected: true,
        },
        TestCase {
            prover_set: vec![BlsScalar::from(3), BlsScalar::from(4)],
            verifier_set: vec![BlsScalar::from(3), BlsScalar::from(4)],
            value: BlsScalar::from(5),
            desc: String::from("Element not part of set, should fail"),
            expected: false,
        },
        TestCase {
            prover_set: vec![BlsScalar::from(3), BlsScalar::from(3)],
            verifier_set: vec![BlsScalar::from(3), BlsScalar::from(3)],
            value: BlsScalar::from(3),
            desc: String::from("Duplicate elements in the set"),
            expected: false,
        },
        TestCase {
            prover_set: vec![BlsScalar::from(3)],
            verifier_set: vec![BlsScalar::from(3), BlsScalar::from(4), BlsScalar::from(5)],
            value: BlsScalar::from(3),
            desc: String::from("Verifier set has different lenght, shouldn't accept trivial proof"),
            expected: false,
        },
        TestCase {
            prover_set: vec![BlsScalar::from(3), BlsScalar::from(4)],
            verifier_set: vec![BlsScalar::from(5), BlsScalar::from(6)],
            value: BlsScalar::from(3),
            desc: String::from("Prover and verifier sets same length, different elements"),
            expected: false,
        },
        TestCase {
            prover_set: vec![BlsScalar::from(3), BlsScalar::from(4)],
            verifier_set: vec![BlsScalar::from(3), BlsScalar::from(6)],
            value: BlsScalar::from(3),
            desc: String::from("Prover and verifier sets same length, some different elements"),
            expected: false,
        },
    ];

    for case in test_cases.iter() {
        println!("{}", case.desc);

        let mut prover = Prover::new(b"testing");
        assert!(circuit(prover.mut_cs(), &case.prover_set, case.value).is_ok());
        let pi = prover.mut_cs().construct_dense_pi_vec().clone();
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        let mut verifier = Verifier::new(b"testing");
        assert!(circuit(verifier.mut_cs(), &case.verifier_set, BlsScalar::zero()).is_ok());
        verifier.preprocess(&ck)?;
        if case.expected {
            assert!(verifier.verify(&proof, &vk, &pi).is_ok());
        } else {
            assert!(verifier.verify(&proof, &vk, &pi).is_err());
        }
    }

    Ok(())
}
