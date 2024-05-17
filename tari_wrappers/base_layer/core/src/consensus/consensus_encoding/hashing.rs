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

use borsh::BorshSerialize;
use digest::Digest;
use tari_common::configuration::Network;
use tari_crypto::hashing::DomainSeparation;
use tari_hashing::DomainSeparatedBorshHasher;

/// Domain separated consensus encoding hasher.
/// This is a thin wrapper around the domain-separated Borsh hasher but adds the network byte in its constructor
/// functions
pub struct DomainSeparatedConsensusHasher<M, D> {
    hasher: DomainSeparatedBorshHasher<M, D>,
}

impl<M: DomainSeparation, D: Digest> DomainSeparatedConsensusHasher<M, D>
where D: Default
{
    pub fn new(label: &'static str) -> Self {
        Self::new_with_network(label, Network::get_current_or_user_setting_or_default())
    }

    pub fn new_with_network(label: &'static str, network: Network) -> Self {
        let hasher = DomainSeparatedBorshHasher::<M, D>::new_with_label(&format!("{}.n{}", label, network.as_byte()));
        Self { hasher }
    }

    pub fn finalize(self) -> digest::Output<D> {
        self.hasher.finalize()
    }

    pub fn update_consensus_encode<T: BorshSerialize>(&mut self, data: &T) {
        self.hasher.update_consensus_encode(data);
    }

    pub fn chain<T: BorshSerialize>(mut self, data: &T) -> Self {
        self.update_consensus_encode(data);
        self
    }
}

impl<M: DomainSeparation, D: Digest + Default> Default for DomainSeparatedConsensusHasher<M, D> {
    /// This `default` implementation is provided for convenience, but should not be used as the de-facto consensus
    /// hasher, rather specify a specific label
    fn default() -> Self {
        DomainSeparatedConsensusHasher::<M, D>::new("default")
    }
}
