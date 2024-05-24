//  Copyright 2023, The Tari Project
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

use std::marker::PhantomData;

use blake2::Blake2b;
use digest::consts::U64;
use tari_common_types::{
    types::{ComAndPubSignature, Commitment, PrivateKey, PublicKey, RangeProof, Signature},
    wallet_types::WalletType,
};
use tari_comms::types::CommsDHKE;
use tari_crypto::{hashing::DomainSeparatedHash, ristretto::RistrettoComSig};
use tari_key_manager::{
    cipher_seed::CipherSeed,
    interface::AddResult,
    key_manager_service::{storage::database::KeyManagerBackend, KeyManagerInterface, KeyManagerServiceError},
    KeyId,
};

use crate::transactions::{
    key_manager::{
        interface::{SecretTransactionKeyManagerInterface, TxoStage},
        TariKeyId,
        TransactionKeyManagerInterface,
    },
    tari_amount::MicroMinotari,
    transaction_components::{
        EncryptedData,
        KernelFeatures,
        RangeProofType,
        TransactionError,
        TransactionInputVersion,
        TransactionKernelVersion,
        TransactionOutput,
        TransactionOutputVersion,
    },
    CryptoFactories,
};

/// The key manager provides a hierarchical key derivation function (KDF) that derives uniformly random secret keys from
/// a single seed key for arbitrary branches, using an implementation of `KeyManagerBackend` to store the current index
/// for each branch.
///
/// This handle can be cloned cheaply and safely shared across multiple threads.
#[derive(Clone)]
pub struct TransactionKeyManagerWrapper<TBackend> {
    transaction_key_manager_inner: PhantomData<TBackend>,
}

pub struct KeyManagerDatabase<TBackend> {
    db: PhantomData<TBackend>,
}

impl<TBackend> TransactionKeyManagerWrapper<TBackend>
where TBackend: KeyManagerBackend<PublicKey> + 'static
{
    /// Creates a new key manager.
    /// * `master_seed` is the primary seed that will be used to derive all unique branch keys with their indexes
    /// * `db` implements `KeyManagerBackend` and is used for persistent storage of branches and indices.
    pub fn new(
        _master_seed: CipherSeed,
        _db: KeyManagerDatabase<TBackend>,
        _crypto_factories: CryptoFactories,
        _wallet_type: WalletType,
    ) -> Result<Self, KeyManagerServiceError> {
        unimplemented!("new")
    }
}

#[async_trait::async_trait]
impl<TBackend> KeyManagerInterface<PublicKey> for TransactionKeyManagerWrapper<TBackend>
where TBackend: KeyManagerBackend<PublicKey> + 'static
{
    async fn add_new_branch<T: Into<String> + Send>(&self, _branch: T) -> Result<AddResult, KeyManagerServiceError> {
        unimplemented!("add_new_branch")
    }

    async fn get_next_key<T: Into<String> + Send>(
        &self,
        _branch: T,
    ) -> Result<(KeyId<PublicKey>, PublicKey), KeyManagerServiceError> {
        unimplemented!("get_next_key")
    }

    async fn get_static_key<T: Into<String> + Send>(
        &self,
        _branch: T,
    ) -> Result<KeyId<PublicKey>, KeyManagerServiceError> {
        unimplemented!("get_static_key")
    }

    async fn get_public_key_at_key_id(&self, _key_id: &KeyId<PublicKey>) -> Result<PublicKey, KeyManagerServiceError> {
        unimplemented!("get_public_key_at_key_id")
    }

    async fn find_key_index<T: Into<String> + Send>(
        &self,
        _branch: T,
        _key: &PublicKey,
    ) -> Result<u64, KeyManagerServiceError> {
        unimplemented!("find_key_index")
    }

    async fn update_current_key_index_if_higher<T: Into<String> + Send>(
        &self,
        _branch: T,
        _index: u64,
    ) -> Result<(), KeyManagerServiceError> {
        unimplemented!("update_current_key_index_if_higher")
    }

    async fn import_key(&self, _private_key: PrivateKey) -> Result<TariKeyId, KeyManagerServiceError> {
        unimplemented!("import_key")
    }
}

#[async_trait::async_trait]
impl<TBackend> TransactionKeyManagerInterface for TransactionKeyManagerWrapper<TBackend>
where TBackend: KeyManagerBackend<PublicKey> + 'static
{
    async fn get_commitment(
        &self,
        _spend_key_id: &TariKeyId,
        _value: &PrivateKey,
    ) -> Result<Commitment, KeyManagerServiceError> {
        unimplemented!("get_commitment")
    }

    async fn verify_mask(
        &self,
        _commitment: &Commitment,
        _spending_key_id: &TariKeyId,
        _value: u64,
    ) -> Result<bool, KeyManagerServiceError> {
        unimplemented!("verify_mask")
    }

    async fn get_recovery_key_id(&self) -> Result<TariKeyId, KeyManagerServiceError> {
        unimplemented!("get_recovery_key_id")
    }

    async fn get_next_spend_and_script_key_ids(
        &self,
    ) -> Result<(TariKeyId, PublicKey, TariKeyId, PublicKey), KeyManagerServiceError> {
        unimplemented!("get_next_spend_and_script_key_ids")
    }

    async fn find_script_key_id_from_spend_key_id(
        &self,
        _spend_key_id: &TariKeyId,
        _public_script_key: Option<&PublicKey>,
    ) -> Result<Option<TariKeyId>, KeyManagerServiceError> {
        unimplemented!("find_script_key_id_from_spend_key_id")
    }

    async fn get_diffie_hellman_shared_secret(
        &self,
        _secret_key_id: &TariKeyId,
        _public_key: &PublicKey,
    ) -> Result<CommsDHKE, TransactionError> {
        unimplemented!("get_diffie_hellman_shared_secret")
    }

    async fn get_diffie_hellman_stealth_domain_hasher(
        &self,
        _secret_key_id: &TariKeyId,
        _public_key: &PublicKey,
    ) -> Result<DomainSeparatedHash<Blake2b<U64>>, TransactionError> {
        unimplemented!("get_diffie_hellman_stealth_domain_hasher")
    }

    async fn import_add_offset_to_private_key(
        &self,
        _secret_key_id: &TariKeyId,
        _offset: PrivateKey,
    ) -> Result<TariKeyId, KeyManagerServiceError> {
        unimplemented!("import_add_offset_to_private_key")
    }

    async fn get_spending_key_id(&self, _public_spending_key: &PublicKey) -> Result<TariKeyId, TransactionError> {
        unimplemented!("get_spending_key_id")
    }

    async fn construct_range_proof(
        &self,
        _spend_key_id: &TariKeyId,
        _value: u64,
        _min_value: u64,
    ) -> Result<RangeProof, TransactionError> {
        unimplemented!("construct_range_proof")
    }

    async fn get_script_signature(
        &self,
        _script_key_id: &TariKeyId,
        _spend_key_id: &TariKeyId,
        _value: &PrivateKey,
        _txi_version: &TransactionInputVersion,
        _script_message: &[u8; 32],
    ) -> Result<ComAndPubSignature, TransactionError> {
        unimplemented!("get_script_signature")
    }

    async fn get_partial_txo_kernel_signature(
        &self,
        _spend_key_id: &TariKeyId,
        _nonce_id: &TariKeyId,
        _total_nonce: &PublicKey,
        _total_excess: &PublicKey,
        _kernel_version: &TransactionKernelVersion,
        _kernel_message: &[u8; 32],
        _kernel_features: &KernelFeatures,
        _txo_type: TxoStage,
    ) -> Result<Signature, TransactionError> {
        unimplemented!("get_partial_txo_kernel_signature")
    }

    async fn get_txo_kernel_signature_excess_with_offset(
        &self,
        _spend_key_id: &TariKeyId,
        _nonce_id: &TariKeyId,
    ) -> Result<PublicKey, TransactionError> {
        unimplemented!("get_txo_kernel_signature_excess_with_offset")
    }

    async fn get_txo_private_kernel_offset(
        &self,
        _spend_key_id: &TariKeyId,
        _nonce_id: &TariKeyId,
    ) -> Result<PrivateKey, TransactionError> {
        unimplemented!("get_txo_private_kernel_offset")
    }

    async fn encrypt_data_for_recovery(
        &self,
        _spend_key_id: &TariKeyId,
        _custom_recovery_key_id: Option<&TariKeyId>,
        _value: u64,
    ) -> Result<EncryptedData, TransactionError> {
        unimplemented!("encrypt_data_for_recovery")
    }

    async fn try_output_key_recovery(
        &self,
        _output: &TransactionOutput,
        _custom_recovery_key_id: Option<&TariKeyId>,
    ) -> Result<(TariKeyId, MicroMinotari), TransactionError> {
        unimplemented!("try_output_key_recovery")
    }

    async fn get_script_offset(
        &self,
        _script_key_ids: &[TariKeyId],
        _sender_offset_key_ids: &[TariKeyId],
    ) -> Result<PrivateKey, TransactionError> {
        unimplemented!("get_script_offset")
    }

    async fn get_metadata_signature_ephemeral_commitment(
        &self,
        _nonce_id: &TariKeyId,
        _range_proof_type: RangeProofType,
    ) -> Result<Commitment, TransactionError> {
        unimplemented!("get_metadata_signature_ephemeral_commitment")
    }

    async fn get_metadata_signature(
        &self,
        _spending_key_id: &TariKeyId,
        _value_as_private_key: &PrivateKey,
        _sender_offset_key_id: &TariKeyId,
        _txo_version: &TransactionOutputVersion,
        _metadata_signature_message: &[u8; 32],
        _range_proof_type: RangeProofType,
    ) -> Result<ComAndPubSignature, TransactionError> {
        unimplemented!("get_metadata_signature")
    }

    async fn get_receiver_partial_metadata_signature(
        &self,
        _spend_key_id: &TariKeyId,
        _value: &PrivateKey,
        _sender_offset_public_key: &PublicKey,
        _ephemeral_pubkey: &PublicKey,
        _txo_version: &TransactionOutputVersion,
        _metadata_signature_message: &[u8; 32],
        _range_proof_type: RangeProofType,
    ) -> Result<ComAndPubSignature, TransactionError> {
        unimplemented!("get_receiver_partial_metadata_signature")
    }

    async fn get_sender_partial_metadata_signature(
        &self,
        _ephemeral_private_nonce_id: &TariKeyId,
        _sender_offset_key_id: &TariKeyId,
        _commitment: &Commitment,
        _ephemeral_commitment: &Commitment,
        _txo_version: &TransactionOutputVersion,
        _metadata_signature_message: &[u8; 32],
    ) -> Result<ComAndPubSignature, TransactionError> {
        unimplemented!("get_sender_partial_metadata_signature")
    }

    async fn generate_burn_proof(
        &self,
        _spending_key: &TariKeyId,
        _amount: &PrivateKey,
        _claim_public_key: &PublicKey,
    ) -> Result<RistrettoComSig, TransactionError> {
        unimplemented!("generate_burn_proof")
    }
}

#[async_trait::async_trait]
impl<TBackend> SecretTransactionKeyManagerInterface for TransactionKeyManagerWrapper<TBackend>
where TBackend: KeyManagerBackend<PublicKey> + 'static
{
    async fn get_private_key(&self, _key_id: &TariKeyId) -> Result<PrivateKey, KeyManagerServiceError> {
        unimplemented!("get_private_key")
    }
}
