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
use crate::Error as GadgetsError;
use alloc::vec::Vec;
use dusk_plonk::prelude::*;

/// Provided a `Vec<BlsScalar>`, constraint `value: BlsScalar` to be in that set
pub fn set_non_membership_gadget(
    composer: &mut StandardComposer,
    set: Vec<BlsScalar>,
    value: BlsScalar,
) -> Result<(), GadgetsError> {
    // Add the `value` to the composer
    let v = AllocatedScalar::allocate(composer, value);

    let mut diff_vars: Vec<AllocatedScalar> = Vec::new();
    let mut diff_inv_vars: Vec<AllocatedScalar> = Vec::new();
    // Add each element from the vector to the composer
    for elem in set.iter() {
        // let elem_assigned = composer.add_input(*elem);
        let diff = elem - value;
        let diff_assigned = AllocatedScalar::allocate(composer, diff);
        diff_vars.push(diff_assigned);

        let diff_inv = diff.invert();

        let diff_inv_assigned: AllocatedScalar;
        if diff_inv.is_some().unwrap_u8() == 1u8 {
            // Safe to unwrap here.
            diff_inv_assigned = AllocatedScalar::allocate(composer, diff_inv.unwrap());
            diff_inv_vars.push(diff_inv_assigned);
        } else {
            return Err(GadgetsError::NonExistingInverse);
        }

        composer.add(
            (BlsScalar::one(), diff_inv_assigned.var),
            (BlsScalar::one(), v.var),
            -elem,
            None,
        );

        // This is basically the is_non_zero method, except that we've already computed the inverses
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
