//  Copyright 2022. The Tari Project
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

use blake2::Blake2b;
use borsh::{BorshDeserialize, BorshSerialize};
use digest::consts::U32;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tari_common_types::{
    epoch::VnEpoch,
    types::{FixedHash, PublicKey, Signature},
};
use tari_hashing::TransactionHashDomain;
use tari_utilities::ByteArray;

use crate::{consensus::DomainSeparatedConsensusHasher, transactions::transaction_components::ValidatorNodeSignature};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorNodeRegistration {
    signature: ValidatorNodeSignature,
}

impl ValidatorNodeRegistration {
    pub fn new(signature: ValidatorNodeSignature) -> Self {
        Self { signature }
    }

    pub fn is_valid_signature_for(&self, msg: &[u8]) -> bool {
        self.signature.is_valid_signature_for(msg)
    }

    pub fn derive_shard_key(
        &self,
        prev_shard_key: Option<[u8; 32]>,
        epoch: VnEpoch,
        interval: VnEpoch,
        block_hash: &FixedHash,
    ) -> [u8; 32] {
        match prev_shard_key {
            Some(prev) => {
                if does_require_new_shard_key(self.public_key(), epoch, interval) {
                    generate_shard_key(self.public_key(), block_hash)
                } else {
                    prev
                }
            },
            None => generate_shard_key(self.public_key(), block_hash),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        self.signature.public_key()
    }

    pub fn signature(&self) -> &Signature {
        self.signature.signature()
    }
}

fn does_require_new_shard_key(public_key: &PublicKey, epoch: VnEpoch, interval: VnEpoch) -> bool {
    let pk = U256::from_big_endian(public_key.as_bytes());
    let epoch = U256::from(epoch.as_u64());
    let interval = U256::from(interval.as_u64());
    (pk + epoch) % interval == U256::zero()
}

fn generate_shard_key(public_key: &PublicKey, entropy: &[u8; 32]) -> [u8; 32] {
    DomainSeparatedConsensusHasher::<TransactionHashDomain, Blake2b<U32>>::new("validator_node_shard_key")
        .chain(public_key)
        .chain(entropy)
        .finalize()
        .into()
}
