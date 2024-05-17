// Copyright 2019 The Tari Project
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

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use tari_crypto::{keys::PublicKey, tari_utilities::byte_array::ByteArrayError};
use zeroize::Zeroize;

use crate::cipher_seed::CipherSeed;

#[derive(Clone, Derivative, Serialize, Deserialize, Zeroize)]
#[derivative(Debug)]
pub struct DerivedKey<PK>
where PK: PublicKey
{
    #[derivative(Debug = "ignore")]
    #[serde(skip_deserializing)]
    pub key: PK::K,
    pub key_index: u64,
}

#[derive(Clone, Derivative, Serialize, Deserialize, Zeroize)]
#[derivative(Debug)]
pub struct DerivedPublicKey<PK>
where PK: PublicKey
{
    #[derivative(Debug = "ignore")]
    #[serde(skip_deserializing)]
    pub key: PK,
    pub key_index: u64,
}

#[derive(Clone, Derivative, PartialEq, Serialize, Deserialize, Zeroize)]
#[derivative(Debug)]
pub struct KeyManager<PK: PublicKey> {
    pub branch_seed: String,
    primary_key_index: u64,
    key: Option<PK>,
}

impl<PK> KeyManager<PK>
where PK: PublicKey
{
    /// Creates a new KeyManager with a new randomly selected entropy
    pub fn new() -> KeyManager<PK> {
        KeyManager {
            branch_seed: "".to_string(),
            primary_key_index: 0,
            key: None,
        }
    }

    /// Constructs a KeyManager from known parts
    pub fn from(branch_seed: String, primary_key_index: u64) -> KeyManager<PK> {
        KeyManager {
            branch_seed,
            primary_key_index,
            key: None,
        }
    }

    /// Derive a new private key from master key: derived_key=H(master_key||branch_seed||index), for some
    /// hash function H which is Length attack resistant, such as Blake2b.
    pub fn derive_key(&self, _key_index: u64) -> Result<DerivedKey<PK>, ByteArrayError> {
        unimplemented!("derive_key")
    }

    /// Derive a new public key from master key: derived_key=H(master_key||branch_seed||index), for some
    /// hash function H which is Length attack resistant, such as Blake2b.
    pub fn derive_public_key(&self, _key_index: u64) -> Result<DerivedPublicKey<PK>, ByteArrayError> {
        unimplemented!("derive_public_key")
    }

    pub fn get_private_key(&self, _key_index: u64) -> Result<PK::K, ByteArrayError> {
        unimplemented!("get_private_key")
    }

    /// Generate next deterministic private key derived from master key
    pub fn next_key(&mut self) -> Result<DerivedKey<PK>, ByteArrayError> {
        unimplemented!("next_key")
    }

    /// Generate next deterministic private key derived from master key
    pub fn increment_key_index(&mut self, _increment: u64) -> u64 {
        unimplemented!("increment_key_index")
    }

    pub fn cipher_seed(&self) -> &CipherSeed {
        unimplemented!("cipher_seed")
    }

    pub fn key_index(&self) -> u64 {
        self.primary_key_index
    }

    pub fn update_key_index(&mut self, new_index: u64) {
        self.primary_key_index = new_index;
    }
}

impl<K> Default for KeyManager<K>
where K: PublicKey
{
    fn default() -> Self {
        Self::new()
    }
}
