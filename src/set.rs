// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Basic gadgets for working with vectors/sets.
//!
//! This module contains gadgets for checking set membership,
//! set non-membership and set uniqueness
use super::AllocatedScalar;
use crate::bit::bit_gadget;
use crate::Error as GadgetsError;
use alloc::vec::Vec;
use dusk_plonk::prelude::*;

/// Provided a `Vec<BlsScalar>`, constraint `value: BlsScalar` to be in that vector
/// Here, the prover and the verifier should have the same view of the vector, i.e.
/// the vector must form part of the circuit
/// This gadget might seem silly in isolation (if I'm a prover and the vector
/// is public and shared, it's trivial to pick an element NOT in that vector)
/// However, it can be combined with other gadgets to prove more power statements, e.g.
/// We are given a collision vector, whose each element hashes to a specific value of interest
/// We now want to prove that we know **another** element in that vector with that property
/// (consider that finding another collision is **hard**)
/// Then we need to prove that we know a new element `x` s.t.:
/// a) it hashes to H, like all current vector elements
/// b) it is not already a member of the vector
pub fn vector_non_membership_gadget(
    composer: &mut StandardComposer,
    vector: &Vec<BlsScalar>,
    value: BlsScalar,
) -> Result<(), GadgetsError> {
    // Add the `value` to the composer
    let v = AllocatedScalar::allocate(composer, value);

    // Add each element from the vector to the composer
    for elem in vector.iter() {
        // Since the vector forms part of the circuit,
        // we should explicitly constrain each variable in the circuit
        // to a constant corresponding to vector's value at that index
        let elem_assigned = composer.add_input(*elem);
        composer.constrain_to_constant(elem_assigned, *elem, None);
        let diff = elem - value;
        let diff_assigned = AllocatedScalar::allocate(composer, diff);

        let diff_inv = diff.invert();

        let diff_inv_assigned: AllocatedScalar;
        if diff_inv.is_some().unwrap_u8() == 1u8 {
            // Safe to unwrap here.
            diff_inv_assigned = AllocatedScalar::allocate(composer, diff_inv.unwrap());
        } else {
            return Err(GadgetsError::NonExistingInverse);
        }

        // since `diff = elem = value`, we first assign a variable
        // for `diff + value`
        let value_plus_diff: Variable = composer.add(
            (BlsScalar::one(), diff_assigned.var),
            (BlsScalar::one(), v.var),
            BlsScalar::zero(),
            // -elem,
            None,
        );

        // And then ensure that this variable equals `elem`,
        // which already is constrained to the vector's value
        composer.assert_equal(value_plus_diff, elem_assigned);

        // This is basically the is_non_zero method, except that we've already computed the inverses
        // ensure that diff*diff_inv = 1
        // TODO: is it really needed? Unlike in Bulletproofs, now the prover
        // doesn't supply committments to inverses.
        // Rather these are calculated as part of the circuit. We already constrain the vector elements
        // to be part of the circuit, i.e. correct, and so if we WERE able to compute the inverse, that
        // means it exists for the given `diff`, i.e. is correct.
        // If inverse didn't exist, then we would have failed with `NonExistingInverse`
        // The problem statement between might differ between Bulletproofs I think
        // In this one the vector is part of the circuit itself
        let one = composer.add_witness_to_circuit_description(BlsScalar::one());
        composer.poly_gate(
            diff_assigned.var,
            diff_inv_assigned.var,
            one,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            None,
        );
    }
    Ok(())
}

/// Constrain the sum of elements in the vector to be `expected_sum`
pub fn vector_sum_gadget(
    composer: &mut StandardComposer,
    vector: &Vec<AllocatedScalar>,
    expected_sum: BlsScalar,
) -> Result<(), GadgetsError> {
    let mut accumulator: Variable = composer.zero_var();

    for i in 0..vector.len() {
        // the accumulated Variable will be the sum of all previous ones
        accumulator = composer.add(
            (BlsScalar::one(), accumulator),
            (BlsScalar::one(), vector[i].var),
            BlsScalar::zero(),
            None,
        );
    }

    // finally, we allocate a variable for the expected sum
    let expected_sum_var = composer.add_input(expected_sum);
    // and constrain the accumulator to be equal to it
    composer.assert_equal(accumulator, expected_sum_var);

    Ok(())
}

/// Provided a `Vec<BlsScalar>`, constraint `value: BlsScalar` to be in that set
pub fn set_membership_gadget(
    composer: &mut StandardComposer,
    set: Vec<BlsScalar>,
    value: BlsScalar,
) -> Result<(), GadgetsError> {
    let bit_map: Vec<u64> = set
        .iter()
        .map(|elem| if *elem == value { 1 } else { 0 })
        .collect();

    let mut assigned_bits: Vec<AllocatedScalar> = Vec::new();
    for bit in bit_map {
        let bit_assigned = AllocatedScalar::allocate(composer, BlsScalar::from(bit));
        assigned_bits.push(bit_assigned);
        assert!(bit_gadget(composer, bit_assigned).is_ok());
    }
    assert!(vector_sum_gadget(composer, &assigned_bits, 1.into()).is_ok());
    Ok(())
}
