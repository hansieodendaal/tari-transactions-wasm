// Copyright 2019. The Tari Project
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

use std::{
    convert::{TryFrom, TryInto},
    fmt::{Display, Error, Formatter},
    iter::Sum,
    ops::{Add, Div, DivAssign, Mul, MulAssign, Sub},
    str::FromStr,
};

use borsh::{BorshDeserialize, BorshSerialize};
use decimal_rs::{Decimal, DecimalConvertError};
use newtype_ops::newtype_ops;
use serde::{Deserialize, Serialize};
use tari_crypto::ristretto::RistrettoSecretKey;
use thiserror::Error as ThisError;

use super::format_currency;

/// All calculations using Tari amounts should use these newtypes to prevent bugs related to rounding errors, unit
/// conversion errors etc.
///
/// ```edition2018
/// use tari_core::transactions::tari_amount::MicroMinotari;
///
/// let a = MicroMinotari::from(500);
/// let b = MicroMinotari::from(50);
/// assert_eq!(a + b, MicroMinotari::from(550));
/// ```
#[derive(
    Copy,
    Default,
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]

/// The minimum spendable unit Tari token amount
pub struct MicroMinotari(pub u64);

#[derive(Debug, Clone, ThisError, PartialEq, Eq)]
pub enum MicroMinotariError {
    #[error("Failed to parse value: {0}")]
    ParseError(String),
    #[error("Failed to convert value: {0}")]
    ConversionError(DecimalConvertError),
}

// DecimalConvertError does not implement Error
impl From<DecimalConvertError> for MicroMinotariError {
    fn from(err: DecimalConvertError) -> Self {
        MicroMinotariError::ConversionError(err)
    }
}
/// A convenience constant that makes it easier to define Tari amounts.
/// ```edition2018
/// use tari_core::transactions::tari_amount::{uT, MicroMinotari, T};
/// assert_eq!(MicroMinotari::from(42), 42 * uT);
/// assert_eq!(1 * T, 1_000_000.into());
/// assert_eq!(3_000_000 * uT, 3 * T);
/// ```
#[allow(non_upper_case_globals)]
pub const uT: MicroMinotari = MicroMinotari(1);
pub const T: MicroMinotari = MicroMinotari(1_000_000);

// You can only add or subtract µT from µT
newtype_ops! { [MicroMinotari] {add sub mul div} {:=} Self Self }
newtype_ops! { [MicroMinotari] {add sub mul div} {:=} &Self &Self }
newtype_ops! { [MicroMinotari] {add sub mul div} {:=} Self &Self }

// Multiplication and division only makes sense when µT is multiplied/divided by a scalar
newtype_ops! { [MicroMinotari] {mul div rem} {:=} Self u64 }
newtype_ops! { [MicroMinotari] {mul div rem} {:=} &Self u64 }

impl Mul<MicroMinotari> for u64 {
    type Output = MicroMinotari;

    fn mul(self, rhs: MicroMinotari) -> Self::Output {
        MicroMinotari(self * rhs.0)
    }
}

impl MicroMinotari {
    pub const fn zero() -> Self {
        Self(0)
    }

    pub fn checked_add<T>(&self, v: T) -> Option<MicroMinotari>
    where T: AsRef<MicroMinotari> {
        self.as_u64().checked_add(v.as_ref().as_u64()).map(Into::into)
    }

    pub fn checked_sub<T>(&self, v: T) -> Option<MicroMinotari>
    where T: AsRef<MicroMinotari> {
        self.as_u64().checked_sub(v.as_ref().as_u64()).map(Into::into)
    }

    pub fn checked_mul<T>(&self, v: T) -> Option<MicroMinotari>
    where T: AsRef<MicroMinotari> {
        self.as_u64().checked_mul(v.as_ref().as_u64()).map(Into::into)
    }

    pub fn checked_div<T>(&self, v: T) -> Option<MicroMinotari>
    where T: AsRef<MicroMinotari> {
        self.as_u64().checked_div(v.as_ref().as_u64()).map(Into::into)
    }

    pub fn saturating_sub<T>(&self, v: T) -> MicroMinotari
    where T: AsRef<MicroMinotari> {
        self.as_u64().saturating_sub(v.as_ref().as_u64()).into()
    }

    pub fn saturating_add<T>(&self, v: T) -> MicroMinotari
    where T: AsRef<MicroMinotari> {
        self.as_u64().saturating_add(v.as_ref().as_u64()).into()
    }

    #[inline]
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    #[inline]
    pub fn as_u128(&self) -> u128 {
        u128::from(self.0)
    }

    pub fn to_currency_string(&self, sep: char) -> String {
        format!("{} µT", format_currency(&self.as_u64().to_string(), sep))
    }
}

impl AsRef<MicroMinotari> for MicroMinotari {
    fn as_ref(&self) -> &MicroMinotari {
        self
    }
}

#[allow(clippy::identity_op)]
impl Display for MicroMinotari {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        if *self < 1 * T {
            write!(f, "{} µT", self.as_u64())
        } else {
            Minotari::from(*self).fmt(f)
        }
    }
}

impl From<MicroMinotari> for u64 {
    fn from(v: MicroMinotari) -> Self {
        v.0
    }
}

impl FromStr for MicroMinotari {
    type Err = MicroMinotariError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let processed = s.replace([',', ' '], "").to_ascii_lowercase();
        // Is this Tari or MicroMinotari
        let is_micro_tari = if processed.ends_with("ut") || processed.ends_with("µt") {
            true
        } else if processed.ends_with('t') {
            false
        } else {
            !processed.contains('.')
        };

        let processed = processed.replace("ut", "").replace("µt", "").replace('t', "");
        if is_micro_tari {
            processed
                .parse::<u64>()
                .map(MicroMinotari::from)
                .map_err(|e| MicroMinotariError::ParseError(e.to_string()))
        } else {
            processed
                .parse::<Decimal>()
                .map_err(|e| MicroMinotariError::ParseError(e.to_string()))
                .and_then(Minotari::try_from)
                .map(MicroMinotari::from)
        }
    }
}

impl From<u64> for MicroMinotari {
    fn from(v: u64) -> Self {
        MicroMinotari(v)
    }
}

impl From<MicroMinotari> for f64 {
    fn from(v: MicroMinotari) -> Self {
        v.0 as f64
    }
}

impl From<Minotari> for MicroMinotari {
    fn from(v: Minotari) -> Self {
        v.0
    }
}

impl From<MicroMinotari> for RistrettoSecretKey {
    fn from(v: MicroMinotari) -> Self {
        v.0.into()
    }
}

impl<'a> Sum<&'a MicroMinotari> for MicroMinotari {
    fn sum<I: Iterator<Item = &'a MicroMinotari>>(iter: I) -> MicroMinotari {
        iter.fold(MicroMinotari::from(0), Add::add)
    }
}

impl Sum<MicroMinotari> for MicroMinotari {
    fn sum<I: Iterator<Item = MicroMinotari>>(iter: I) -> MicroMinotari {
        iter.fold(MicroMinotari::from(0), Add::add)
    }
}

impl Add<Minotari> for MicroMinotari {
    type Output = Self;

    fn add(self, rhs: Minotari) -> Self::Output {
        self + rhs.0
    }
}

impl Sub<Minotari> for MicroMinotari {
    type Output = Self;

    fn sub(self, rhs: Minotari) -> Self::Output {
        self - rhs.0
    }
}

/// A convenience struct for representing full Tari.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd)]
pub struct Minotari(MicroMinotari);

newtype_ops! { [Minotari] {add sub mul div} {:=} Self Self }
newtype_ops! { [Minotari] {add sub mul div} {:=} &Self &Self }
newtype_ops! { [Minotari] {add sub mul div} {:=} Self &Self }

// You can only add or subtract µT from µT
newtype_ops! { [Minotari] {add sub mul div} {:=} Self MicroMinotari }
newtype_ops! { [Minotari] {add sub mul div} {:=} &Self &MicroMinotari }
newtype_ops! { [Minotari] {add sub mul div} {:=} Self &MicroMinotari }

impl Minotari {
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Into::into)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Into::into)
    }

    pub fn checked_mul(self, other: Self) -> Option<Self> {
        self.0.checked_mul(other.0).map(Into::into)
    }

    pub fn checked_div(self, other: Self) -> Option<Self> {
        self.0.checked_div(other.0).map(Into::into)
    }

    pub fn to_currency_string(&self, sep: char) -> String {
        // UNWRAP: MAX_I128_REPR > u64::MAX and scale is within bounds (see Decimal::from_parts)
        let d = Decimal::from_parts(u128::from(self.0.as_u64()), 6, false).unwrap();
        format!("{} T", format_currency(&d.to_string(), sep))
    }
}

impl From<MicroMinotari> for Minotari {
    fn from(v: MicroMinotari) -> Self {
        Self(v)
    }
}

impl From<u64> for Minotari {
    fn from(v: u64) -> Self {
        Self((v * 1_000_000).into())
    }
}

impl TryFrom<Decimal> for Minotari {
    type Error = MicroMinotariError;

    /// Converts Decimal into Minotari up to the first 6 decimal values. This will return an error if:
    /// 1. the value is negative,
    /// 1. the value has more than 6 decimal places (scale > 6)
    /// 1. the value exceeds u64::MAX
    fn try_from(v: Decimal) -> Result<Self, Self::Error> {
        if v.is_sign_negative() {
            Err(MicroMinotariError::ParseError("value cannot be negative".to_string()))
        } else if v.scale() > 6 {
            Err(MicroMinotariError::ParseError(format!("too many decimals ({})", v)))
        } else {
            let (micro_tari, _, _) = (v * 1_000_000u64).trunc(0).into_parts();
            let micro_tari = micro_tari.try_into().map_err(|_| DecimalConvertError::Overflow)?;
            Ok(Self(MicroMinotari(micro_tari)))
        }
    }
}

impl FromStr for Minotari {
    type Err = MicroMinotariError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.to_ascii_lowercase().contains('t') {
            let val = MicroMinotari::from_str(s)?;
            Ok(Minotari::from(val))
        } else {
            let d = Decimal::from_str(s).map_err(|e| MicroMinotariError::ParseError(e.to_string()))?;
            Self::try_from(d)
        }
    }
}

impl Display for Minotari {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let d1 = Decimal::from(self.0.as_u64());
        let d2 = Decimal::try_from(1_000_000f64).expect("will succeed");
        let precision = f.precision().unwrap_or(6);
        write!(f, "{1:.*} T", precision, d1 / d2)
    }
}

impl Mul<u64> for Minotari {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        (self.0 * rhs).into()
    }
}

impl MulAssign<u64> for Minotari {
    fn mul_assign(&mut self, rhs: u64) {
        self.0 *= rhs;
    }
}

impl Div<u64> for Minotari {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        (self.0 / rhs).into()
    }
}

impl DivAssign<u64> for Minotari {
    fn div_assign(&mut self, rhs: u64) {
        self.0 /= rhs;
    }
}
