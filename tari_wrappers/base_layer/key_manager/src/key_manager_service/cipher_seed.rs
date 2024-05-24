// Copyright 2021. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use serde::{Deserialize, Serialize};
use tari_utilities::SafePassword;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::KeyManagerError;

/// This is a non-implementation of a Cipher Seed.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CipherSeed {
    version: u8,
    birthday: u16,
}

impl CipherSeed {
    /// Generate a new seed
    pub fn new() -> Self {
        unimplemented!("CipherSeed::new is not implemented")
    }

    /// Generate an encrypted seed from a passphrase
    pub fn encipher(&self, _passphrase: Option<SafePassword>) -> Result<Vec<u8>, KeyManagerError> {
        unimplemented!("CipherSeed::encipher is not implemented")
    }

    /// Recover a seed from encrypted data and a passphrase
    pub fn from_enciphered_bytes(
        _encrypted_seed: &[u8],
        _passphrase: Option<SafePassword>,
    ) -> Result<Self, KeyManagerError> {
        unimplemented!("CipherSeed::from_enciphered_bytes is not implemented")
    }

    /// Get a reference to the seed entropy
    pub fn entropy(&self) -> &[u8] {
        unimplemented!("CipherSeed::entropy is not implemented")
    }

    /// Get the seed birthday
    pub fn birthday(&self) -> u16 {
        unimplemented!("CipherSeed::birthday is not implemented")
    }
}

impl Default for CipherSeed {
    fn default() -> Self {
        Self::new()
    }
}
