// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use blake2::Blake2b;
use digest::consts::U64;
use tari_hashing::ConfidentialOutputHashDomain;

use crate::consensus::DomainSeparatedConsensusHasher;

pub mod borsh;
pub mod byte_counter;
pub mod limited_reader;
pub mod one_sided;

/// Hasher used in the DAN to derive masks and encrypted value keys
pub type ConfidentialOutputHasher = DomainSeparatedConsensusHasher<ConfidentialOutputHashDomain, Blake2b<U64>>;
