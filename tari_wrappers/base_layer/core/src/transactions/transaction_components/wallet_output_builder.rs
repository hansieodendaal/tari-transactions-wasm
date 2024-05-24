//  Copyright 2021. The Tari Project
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

use derivative::Derivative;
use tari_common_types::types::{ComAndPubSignature, PublicKey};
use tari_script::{ExecutionStack, TariScript};

use crate::{
    covenants::Covenant,
    transactions::{
        key_manager::{TariKeyId, TransactionKeyManagerInterface},
        tari_amount::MicroMinotari,
        transaction_components::{
            EncryptedData,
            OutputFeatures,
            TransactionError,
            TransactionOutput,
            TransactionOutputVersion,
            WalletOutput,
        },
    },
};

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct WalletOutputBuilder {
    version: TransactionOutputVersion,
    value: MicroMinotari,
    spending_key_id: TariKeyId,
    features: OutputFeatures,
    script: Option<TariScript>,
    covenant: Covenant,
    input_data: Option<ExecutionStack>,
    script_key_id: Option<TariKeyId>,
    sender_offset_public_key: Option<PublicKey>,
    metadata_signature: Option<ComAndPubSignature>,
    metadata_signed_by_receiver: bool,
    metadata_signed_by_sender: bool,
    encrypted_data: EncryptedData,
    custom_recovery_key_id: Option<TariKeyId>,
    minimum_value_promise: MicroMinotari,
}

#[allow(dead_code)]
impl WalletOutputBuilder {
    pub fn new(value: MicroMinotari, spending_key_id: TariKeyId) -> Self {
        Self {
            version: TransactionOutputVersion::get_current_version(),
            value,
            spending_key_id,
            features: OutputFeatures::default(),
            script: None,
            covenant: Covenant::default(),
            input_data: None,
            script_key_id: None,
            sender_offset_public_key: None,
            metadata_signature: None,
            metadata_signed_by_receiver: false,
            metadata_signed_by_sender: false,
            encrypted_data: EncryptedData::default(),
            custom_recovery_key_id: None,
            minimum_value_promise: MicroMinotari::zero(),
        }
    }

    pub fn with_sender_offset_public_key(mut self, sender_offset_public_key: PublicKey) -> Self {
        self.sender_offset_public_key = Some(sender_offset_public_key);
        self
    }

    pub fn with_features(mut self, features: OutputFeatures) -> Self {
        self.features = features;
        self
    }

    pub fn with_script(mut self, script: TariScript) -> Self {
        self.script = Some(script);
        self
    }

    pub fn with_input_data(mut self, input_data: ExecutionStack) -> Self {
        self.input_data = Some(input_data);
        self
    }

    pub fn with_covenant(mut self, covenant: Covenant) -> Self {
        self.covenant = covenant;
        self
    }

    pub async fn encrypt_data_for_recovery<KM: TransactionKeyManagerInterface>(
        mut self,
        key_manager: &KM,
        custom_recovery_key_id: Option<&TariKeyId>,
    ) -> Result<Self, TransactionError> {
        self.encrypted_data = key_manager
            .encrypt_data_for_recovery(&self.spending_key_id, custom_recovery_key_id, self.value.as_u64())
            .await?;
        Ok(self)
    }

    pub fn with_script_key(mut self, script_key_id: TariKeyId) -> Self {
        self.script_key_id = Some(script_key_id);
        self
    }

    pub fn with_version(mut self, version: TransactionOutputVersion) -> Self {
        self.version = version;
        self
    }

    pub fn with_minimum_value_promise(mut self, minimum_value_promise: MicroMinotari) -> Self {
        self.minimum_value_promise = minimum_value_promise;
        self
    }

    pub fn value(&self) -> MicroMinotari {
        self.value
    }

    pub fn features(&self) -> &OutputFeatures {
        &self.features
    }

    pub fn script(&self) -> Option<&TariScript> {
        self.script.as_ref()
    }

    pub fn covenant(&self) -> &Covenant {
        &self.covenant
    }

    pub async fn sign_as_sender_and_receiver<KM: TransactionKeyManagerInterface>(
        mut self,
        key_manager: &KM,
        sender_offset_key_id: &TariKeyId,
    ) -> Result<Self, TransactionError> {
        let script = self
            .script
            .as_ref()
            .ok_or_else(|| TransactionError::BuilderError("Cannot sign metadata without a script".to_string()))?;
        let sender_offset_public_key = key_manager.get_public_key_at_key_id(sender_offset_key_id).await?;
        let metadata_message = TransactionOutput::metadata_signature_message_from_parts(
            &self.version,
            script,
            &self.features,
            &self.covenant,
            &self.encrypted_data,
            &self.minimum_value_promise,
        );
        let metadata_signature = key_manager
            .get_metadata_signature(
                &self.spending_key_id,
                &self.value.into(),
                sender_offset_key_id,
                &self.version,
                &metadata_message,
                self.features.range_proof_type,
            )
            .await?;
        self.metadata_signature = Some(metadata_signature);
        self.metadata_signed_by_receiver = true;
        self.metadata_signed_by_sender = true;
        self.sender_offset_public_key = Some(sender_offset_public_key);
        Ok(self)
    }

    pub async fn try_build<KM: TransactionKeyManagerInterface>(
        self,
        key_manager: &KM,
    ) -> Result<WalletOutput, TransactionError> {
        if !self.metadata_signed_by_receiver {
            return Err(TransactionError::BuilderError(
                "Cannot build output because it has not been signed by the receiver".to_string(),
            ));
        }
        if !self.metadata_signed_by_sender {
            return Err(TransactionError::BuilderError(
                "Cannot build output because it has not been signed by the sender".to_string(),
            ));
        }
        let ub = WalletOutput::new(
            self.version,
            self.value,
            self.spending_key_id,
            self.features,
            self.script
                .ok_or_else(|| TransactionError::BuilderError("script must be set".to_string()))?,
            self.input_data
                .ok_or_else(|| TransactionError::BuilderError("input_data must be set".to_string()))?,
            self.script_key_id
                .ok_or_else(|| TransactionError::BuilderError("script_private_key must be set".to_string()))?,
            self.sender_offset_public_key
                .ok_or_else(|| TransactionError::BuilderError("sender_offset_public_key must be set".to_string()))?,
            self.metadata_signature
                .ok_or_else(|| TransactionError::BuilderError("metadata_signature must be set".to_string()))?,
            0,
            self.covenant,
            self.encrypted_data,
            self.minimum_value_promise,
            key_manager,
        )
        .await?;
        Ok(ub)
    }
}
