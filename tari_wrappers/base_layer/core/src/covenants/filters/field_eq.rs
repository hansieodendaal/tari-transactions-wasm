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

use crate::covenants::{
    arguments::CovenantArg,
    context::CovenantContext,
    error::CovenantError,
    filters::Filter,
    output_set::OutputSet,
};

/// Holding struct for the "fields equal" filter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldEqFilter;

impl Filter for FieldEqFilter {
    // Filters out all outputs that do not have the specified output field equal to the specified value based on the
    // next two arguments in the covenant context.
    fn filter(&self, context: &mut CovenantContext<'_>, output_set: &mut OutputSet<'_>) -> Result<(), CovenantError> {
        let field = context.next_arg()?.require_outputfield()?;
        let arg = context.next_arg()?;
        output_set.retain(|output| {
            #[allow(clippy::enum_glob_use)]
            use CovenantArg::*;
            match &arg {
                Hash(hash) => field.is_eq(output, hash),
                PublicKey(pk) => field.is_eq(output, pk),
                Commitment(commitment) => field.is_eq(output, commitment),
                TariScript(script) => field.is_eq(output, script),
                Covenant(covenant) => field.is_eq(output, covenant),
                OutputType(output_type) => field.is_eq(output, output_type),
                Uint(int) => {
                    let val = field
                        .get_field_value_ref::<u64>(output)
                        .copied()
                        .or_else(|| field.get_field_value_ref::<u32>(output).map(|v| u64::from(*v)));

                    match val {
                        Some(val) => Ok(val == *int),
                        None => Err(CovenantError::InvalidArgument {
                            filter: "fields_eq",
                            details: "Uint argument cannot be compared to non-numeric field".to_string(),
                        }),
                    }
                },
                Bytes(bytes) => field.is_eq(output, bytes),
                OutputField(_) | OutputFields(_) => Err(CovenantError::InvalidArgument {
                    filter: "field_eq",
                    details: "Invalid argument: fields are not a valid argument for field_eq".to_string(),
                }),
            }
        })?;

        Ok(())
    }
}
