// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use serde::{Deserialize, Serialize};
use minotari_wallet::output_source::OutputSource;
use tari_common_types::types::{PrivateKey, PublicKey};
use tari_comms::types::CommsDHKE;
use tari_core::{
    one_sided::{
        diffie_hellman_stealth_domain_hasher,
        shared_secret_to_output_encryption_key,
        stealth_address_script_spending_key,
    },
    transactions::{
        transaction_components::{EncryptedData, TransactionOutput},
        CryptoFactories,
    },
};
use tari_crypto::{
    keys::{PublicKey as PK, SecretKey},
    tari_utilities::hex::Hex,
};
use tari_script::Opcode;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{no_match, scan_error, RecoveredOutputResult};

/// A struct to pass data to the output scanning function
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanOutput {
    /// The list of known script keys
    known_script_keys: Vec<PrivateKey>,
    /// The wallet secret key
    wallet_sk: PrivateKey,
    /// The transaction output to be scanned
    output: TransactionOutput,
}

/// Scans a transaction output for a one-sided payment belonging to this wallet. The output is scanned for a one-sided
/// payment using the provided wallet secret key and known script keys. The output is decrypted and verified using the
/// shared secret derived from the wallet secret key and the sender's offset public key.
#[wasm_bindgen]
pub fn scan_output_for_one_sided_payment(val: JsValue) -> JsValue {
    let scan_output: ScanOutput = match serde_wasm_bindgen::from_value(val) {
        Ok(val) => val,
        Err(e) => return scan_error(&format!("scan_output: {e}")),
    };

    let mut known_keys: Vec<(PublicKey, PrivateKey)> = Vec::new();
    for script_key in scan_output.known_script_keys {
        known_keys.push((PublicKey::from_secret_key(&script_key), script_key));
    }

    let wallet_sk = scan_output.wallet_sk;
    let wallet_pk = PublicKey::from_secret_key(&wallet_sk);

    let output = scan_output.output;

    let (output, output_source, script_private_key, shared_secret) = match output.script.as_slice() {
        // ----------------------------------------------------------------------------
        // simple one-sided address
        [Opcode::PushPubKey(scanned_pk)] => {
            match known_keys.iter().find(|x| &x.0 == scanned_pk.as_ref()) {
                // none of the keys match, skipping
                None => return no_match(),

                // match found
                Some(matched_key) => {
                    let shared_secret = CommsDHKE::new(&matched_key.1, &output.sender_offset_public_key);
                    (
                        output.clone(),
                        OutputSource::OneSided,
                        matched_key.1.clone(),
                        shared_secret,
                    )
                },
            }
        },

        // ----------------------------------------------------------------------------
        // one-sided stealth address
        // NOTE: Extracting the nonce R and a spending (public aka scan_key) key from the script
        // NOTE: [RFC 203 on Stealth Addresses](https://rfc.tari.com/RFC-0203_StealthAddresses.html)
        [Opcode::PushPubKey(nonce), Opcode::Drop, Opcode::PushPubKey(scanned_pk)] => {
            // matching spending (public) keys
            let stealth_address_hasher = diffie_hellman_stealth_domain_hasher(&wallet_sk, nonce.as_ref());
            let script_spending_key = stealth_address_script_spending_key(&stealth_address_hasher, &wallet_pk);
            if &script_spending_key != scanned_pk.as_ref() {
                return no_match();
            }

            // Compute the stealth address offset
            let stealth_address_offset = PrivateKey::from_uniform_bytes(stealth_address_hasher.as_ref())
                .expect("'DomainSeparatedHash<Blake2b<U64>>' has correct size");
            let script_private_key = wallet_sk.clone() + stealth_address_offset;

            let shared_secret = CommsDHKE::new(&wallet_sk, &output.sender_offset_public_key);
            (
                output.clone(),
                OutputSource::StealthOneSided,
                script_private_key,
                shared_secret,
            )
        },

        _ => return no_match(),
    };

    verify_onesided_output(&output, output_source, &script_private_key, &shared_secret)
}

fn verify_onesided_output(
    output: &TransactionOutput,
    output_source: OutputSource,
    script_private_key: &PrivateKey,
    shared_secret: &CommsDHKE,
) -> JsValue {
    let encryption_key = match shared_secret_to_output_encryption_key(shared_secret) {
        Ok(key) => key,
        Err(e) => return scan_error(&format!("Could not derive encryption key: {e}")),
    };
    let crypto_factories = CryptoFactories::default();
    if let Ok((committed_value, spending_key)) =
        EncryptedData::decrypt_data(&encryption_key, &output.commitment, &output.encrypted_data)
    {
        match output.verify_mask(&crypto_factories.range_proof, &spending_key, committed_value.into()) {
            Ok(verified) => {
                if verified {
                    let result = RecoveredOutputResult {
                        hash: Some(output.hash().to_hex()),
                        output_source: Some(output_source.to_string()),
                        output_type: Some(output.features.output_type.to_string()),
                        value: Some(committed_value.as_u64()),
                        spending_key: Some(spending_key.to_hex()),
                        script_key: Some(script_private_key.to_hex()),
                        error: None,
                        maturity: None,
                    };
                    serde_wasm_bindgen::to_value(&result).unwrap()
                } else {
                    no_match()
                }
            },
            Err(e) => scan_error(&format!("Could not verify output: {e}")),
        }
    } else {
        no_match()
    }
}

#[cfg(test)]
mod test {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn it_identifies_a_known_output() {
        let commitment = "2a1a8b875b59789fe028b5500f71efadc37bc10a2c2e05f92cdd76362d9ab258".to_string();
        let spending_key = "699b09f32420ac4ac39d926f10fb169409d446f80651e33d8454ff359dd9bb2460231eb03a33004685f44bc21854479b86816e614c326fe559097330238122f650cde9d5e8a8c8cc".to_string();
        let script_key = "5de8d512aff4874143bd16b563930cad743cd29e27ae85c38f11556073e52706c772b75e36c7d97fe60f928e8fb6ab6fca5b1a72013ccde69ab131ad01a0a4553f61ed73bf190412".to_string();
        let known_script = "7ee42dc80adda2a5f04c9e56601c996ab6bbf94de29e478426e7f4b6e0b908f85b".to_string();

    }

    #[wasm_bindgen_test]
    fn it_does_not_identify_an_unknown_output() {

    }
}