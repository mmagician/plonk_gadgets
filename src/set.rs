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

/// Provided a `Vec<BlsScalar>`, constraint `value` to not be in that vector
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
    value: AllocatedScalar,
) -> Result<(), GadgetsError> {
    // Add each element from the vector to the composer
    for elem in vector.iter() {
        // Since the vector forms part of the circuit,
        // we should explicitly constrain each variable in the circuit
        // to a constant corresponding to vector's value at that index
        let elem_assigned = composer.add_input(*elem);
        composer.constrain_to_constant(elem_assigned, *elem, None);
        let diff = elem - value.scalar;
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
            (BlsScalar::one(), value.var),
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
/// We are not assuming the public knowledge of vector
/// Simply, we enforce that variables in the circuit allocated
/// to vector's elements sum up s.t. their sum is constrained to `expected_sum`:
/// v_1 + v_2 + ... + v_n = expected_sum
pub fn vector_sum_gadget(
    composer: &mut StandardComposer,
    vector: &Vec<AllocatedScalar>,
    expected_sum: u64,
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

    // and constrain the accumulator to be equal to it
    // Now the expected sum is not part of the circuit,
    // hence we place it as Public Input
    composer.constrain_to_constant(
        accumulator,
        BlsScalar::zero(),
        Some(-BlsScalar::from(expected_sum)),
    );

    Ok(())
}

/// Constrain the product of vector[i] * bits_vector[i] == value * bits_vector[i]
pub fn vector_product_gadget(
    composer: &mut StandardComposer,
    vector: &Vec<AllocatedScalar>,
    bits_vector: &Vec<AllocatedScalar>,
    value: AllocatedScalar,
) -> Result<(), GadgetsError> {
    // TODO need unit tests for this gadget!
    assert_eq!(vector.len(), bits_vector.len());
    let mut accumulator: Variable = composer.zero_var();
    for i in 0..vector.len() {
        let left = composer.mul(
            BlsScalar::one(),
            vector[i].var,
            bits_vector[i].var,
            BlsScalar::zero(),
            None,
        );
        let right = composer.mul(
            BlsScalar::one(),
            value.var,
            bits_vector[i].var,
            BlsScalar::zero(),
            None,
        );
        composer.assert_equal(left, right);
        accumulator = composer.add(
            (BlsScalar::one(), accumulator),
            (BlsScalar::one(), left),
            BlsScalar::zero(),
            None,
        );
    }

    // // and constrain the accumulator to be equal to it
    composer.assert_equal(accumulator, value.var);

    Ok(())
}

/// Analogous to vector_non_membership_gadget
pub fn set_membership_gadget(
    composer: &mut StandardComposer,
    vector: &Vec<BlsScalar>,
    assigned_value: AllocatedScalar,
) -> Result<(), GadgetsError> {
    let mut assigned_set: Vec<AllocatedScalar> = Vec::with_capacity(vector.len());
    for elem in vector.iter() {
        // Since the vector forms part of the circuit,
        // we should explicitly constrain each variable in the circuit
        // to a constant corresponding to vector's value at that index
        let elem_assigned = AllocatedScalar::allocate(composer, *elem);
        composer.constrain_to_constant(elem_assigned.var, *elem, None);
        assigned_set.push(elem_assigned);
    }
    let bit_map: Vec<u64> = vector
        .iter()
        .map(|elem| if *elem == assigned_value.scalar { 1 } else { 0 })
        .collect();

    let mut assigned_bits: Vec<AllocatedScalar> = Vec::new();
    for bit in bit_map {
        let bit_assigned = AllocatedScalar::allocate(composer, BlsScalar::from(bit));
        assigned_bits.push(bit_assigned);
        assert!(bit_gadget(composer, bit_assigned).is_ok());
    }
    assert!(vector_sum_gadget(composer, &assigned_bits, 1).is_ok());

    assert!(vector_product_gadget(composer, &assigned_set, &assigned_bits, assigned_value).is_ok());
    Ok(())
}

/// Given a `set_length`, construct a circuit
/// for proving that all elements in that set are unique
/// This gadget assumes nothing about the individual elements in the set
/// i.e. the set we are proving is not Public Input and is unknown to the verifier
/// In order to construct a correct circuit though, the verifier needs to provide
/// a <placeholder> vector with all elements distinct, and of the same size as verifier's
/// (i.e. the knowledge of the vector length is public!)
pub fn set_uniqueness_gadget(
    composer: &mut StandardComposer,
    vector: &Vec<AllocatedScalar>,
) -> Result<(), GadgetsError> {
    // Recall formula for partial sum: n*(n+1)/2
    let length = vector.len() as usize;
    assert!(length >= 2, "Can't take differences for sets of length < 2");
    // First, make a vector of differences between each element with one another
    // How many differences do we have?
    // For 1st element: n-1 differences
    // All the way down to (n-1)th element with 1 difference
    // That's a partial sum from 1 to n-1, in reverse order
    for i in 0..length {
        for j in (i + 1)..length {
            let diff = vector[i].scalar - vector[j].scalar;
            let diff_assigned = AllocatedScalar::allocate(composer, diff);
            let diff_inv = diff.invert();
            let diff_inv_assigned: AllocatedScalar;
            if diff_inv.is_some().unwrap_u8() == 1u8 {
                // Safe to unwrap here.
                diff_inv_assigned = AllocatedScalar::allocate(composer, diff_inv.unwrap());
            } else {
                return Err(GadgetsError::NonExistingInverse);
            }
            // First check: var allocated to diff is really
            // the difference of two consecutive elements:
            // diff + vector[j] == vector[i]
            let diff_plus_ith_elem = composer.add(
                (BlsScalar::one(), diff_assigned.var),
                (BlsScalar::one(), vector[j].var),
                BlsScalar::zero(),
                None,
            );
            composer.assert_equal(diff_plus_ith_elem, vector[i].var);

            // Second check: diff is non-zero
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
    }
    Ok(())
}
