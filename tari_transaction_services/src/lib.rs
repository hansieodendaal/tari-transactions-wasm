// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Tari-Transactions-Wasm
#[macro_use]
extern crate std;

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

mod scan_outputs;
mod scan_outputs_ledger;

/// A struct to hold the parameters for a successful one-sided payment output recovery
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RecoveredOutputResult {
    /// The hash of the output (hex value)
    pub hash: Option<String>,
    /// The output source
    pub output_source: Option<String>,
    /// The output type
    pub output_type: Option<String>,
    /// The output value
    pub value: Option<u64>,
    /// The output spending private key (hex value)
    pub spending_key: Option<String>,
    /// The script private key (hex value)
    pub script_key: Option<String>,
    /// The output lock height
    pub maturity: Option<u64>,
    /// An error message in cased of an error
    pub error: Option<String>,
}

/// Returns a scan error message
pub fn scan_error(error: &str) -> JsValue {
    let scan_result = RecoveredOutputResult {
        error: Some(error.to_string()),
        ..Default::default()
    };
    serde_wasm_bindgen::to_value(&scan_result).unwrap()
}

/// Returns a no match message
pub fn no_match() -> JsValue {
    serde_wasm_bindgen::to_value(&RecoveredOutputResult::default()).unwrap()
}
