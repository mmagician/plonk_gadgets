// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Basic `Scalar` oriented gadgets collection.
//!
//! This module actually contains conditional selection implementations as
//! well as equalty-checking gadgets.
use super::AllocatedScalar;
use crate::Error as GadgetsError;
use dusk_plonk::prelude::*;

/// Constrain `x` to be a bit
pub fn bit_gadget(composer: &mut StandardComposer, x: AllocatedScalar) -> Result<(), GadgetsError> {
    let one_minus_x = AllocatedScalar::allocate(composer, BlsScalar::one() - x.scalar);

    // constrain x + one_minux_x = 1
    let sum = composer.add(
        (BlsScalar::one(), one_minus_x.var),
        (BlsScalar::one(), x.var),
        BlsScalar::zero(),
        None,
    );
    composer.constrain_to_constant(sum, BlsScalar::one(), None);

    // constrain x * (1-x) == 0
    composer.poly_gate(
        x.var,
        one_minus_x.var,
        composer.zero_var(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        None,
    );
    Ok(())
}
