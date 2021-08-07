// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate dusk_plonk;
extern crate plonk_gadgets;

use dusk_plonk::prelude::*;
use plonk_gadgets::{AllocatedScalar, BitGadgets::*, Error as GadgetError};

#[test]
fn test_is_bit() -> Result<(), Error> {
    // Generate Composer & Public Parameters
    let pub_params = PublicParameters::setup(1 << 10, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 9)?;

    let circuit = |composer: &mut StandardComposer, bit: u64| -> Result<(), GadgetError> {
        let a = AllocatedScalar::allocate(composer, BlsScalar::from(bit));

        bit_gadget(composer, a)
    };

    struct TestCase {
        val: u64,
        expected: bool,
    };

    let test_cases: Vec<TestCase> = vec![
        TestCase {
            val: 0,
            expected: true,
        },
        TestCase {
            val: 1,
            expected: true,
        },
        TestCase {
            val: 2,
            expected: false,
        },
    ];

    for case in test_cases.iter() {
        let mut prover = Prover::new(b"testing");
        assert!(circuit(prover.mut_cs(), case.val).is_ok());
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        let mut verifier = Verifier::new(b"testing");
        assert!(circuit(verifier.mut_cs(), 0).is_ok());
        verifier.preprocess(&ck).expect("Preprocessing error");
        if case.expected {
            assert!(verifier
                .verify(&proof, &vk, &vec![BlsScalar::zero()])
                .is_ok())
        } else {
            assert!(verifier
                .verify(&proof, &vk, &vec![BlsScalar::zero()])
                .is_err())
        };
    }

    Ok(())
}
