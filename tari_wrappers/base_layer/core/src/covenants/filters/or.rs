//  Copyright 2021, The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::covenants::{context::CovenantContext, error::CovenantError, filters::Filter, output_set::OutputSet};

/// Holding struct for the "or" filter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrFilter;

impl Filter for OrFilter {
    // The or filter only removes outputs in the mutable output set that are removed when applying both filters in the
    // covenant context independently from each other. The union of the two outputs sets are returned.
    fn filter(&self, context: &mut CovenantContext<'_>, output_set: &mut OutputSet<'_>) -> Result<(), CovenantError> {
        let a = context.require_next_filter()?;
        let mut output_set_a = output_set.clone();
        a.filter(context, &mut output_set_a)?;

        let b = context.require_next_filter()?;
        let mut output_set_b = output_set.clone();
        b.filter(context, &mut output_set_b)?;

        output_set.set(output_set_a.union(&output_set_b));
        Ok(())
    }
}
