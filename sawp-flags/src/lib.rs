//! Bitflags handling and storage.
//!
//! This crate allows you to define flag values using an enum and derive
//! `BitFlags` to add convenience methods.
//!
//! This implementation was heavily inspired by
//! [enumflags2](https://crates.io/crates/enumflags2) and
//! [bitflags](https://crates.io/crates/bitflags) and customized for use in a
//! sawp parser. Consider using those two open source projects before resorting
//! to this one. One key feature is that we are automatically generating ffi
//! accessors using the [sawp-ffi](https://crates.io/crates/sawp-ffi) crate.
//!
//! This crate works as follows:
//! - `enum YourEnum` with a numeric representation (e.g. `#[repr(u8)]`) is used
//!   to define bit fields.
//! - deriving `BitFlags` on this enum will add convenience methods for bitwise
//!   operations and implement the `Flag` trait.
//! - Flag values are transparently stored as `Flags<YourEnum>` so you can perform
//!   more operations on this type.
//!
//! # Example
//! See `example` module for a generated example as well.
//! ```
//! use sawp_flags::{BitFlags, Flags, Flag};
//!
//! /// Example enum
//! #[derive(Debug, Clone, Copy, PartialEq, BitFlags)]
//! #[repr(u8)]
//! pub enum Test {
//!     A = 0b0001,
//!     B = 0b0010,
//!     C = 0b0100,
//!     D = 0b1000,
//!     /// Variants can be a bitmask of the other fields like so
//!     E = Test::A as u8 | Test::B as u8 | Test::C as u8 | Test::D as u8,
//! }
//!
//! // `flags` will be of transparent type `Flags<Test>`
//! let flags : Flags<Test> = Test::A | Test::C;
//!
//! // convert a number to flags using `from_bits()`
//! assert_eq!(flags, Flags::<Test>::from_bits(0b101));
//!
//! // convert flags to a number using `bits()`
//! assert_eq!(0b101, flags.bits());
//!
//! // perform bitwise operations
//! assert_eq!(Test::A | Test::B | Test::C, flags | Test::B);
//! assert_eq!(Test::A, flags & Test::A);
//! assert_eq!(Test::C, flags ^ Test::A);
//!
//! // check which flags are set
//! assert!(flags.contains(Test::A));
//! assert!(!flags.contains(Test::A | Test::B));
//! assert!(flags.intersects(Test::A));
//! assert!(flags.intersects(Test::A | Test::B));
//! ```

use std::ops::*;

/// The `BitFlags` derive macro will implement the `Flags` Trait on your enum and
/// provide convenience methods for bit operations and type conversions.
///
// Re-export derive macro for convenience.
pub use sawp_flags_derive::BitFlags;

/// A primitive numeric type to be used for flag storage.
pub trait Primitive:
    Default
    + BitOr<Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + BitXor<Self, Output = Self>
    + Not<Output = Self>
    + PartialOrd<Self>
    + std::fmt::Debug
    + std::fmt::Binary
    + Copy
    + Clone
{
}

impl Primitive for u8 {}
impl Primitive for u16 {}
impl Primitive for u32 {}
impl Primitive for u64 {}
impl Primitive for u128 {}

/// A trait implemented by all flag enums.
pub trait Flag: Copy + Clone + std::fmt::Debug + std::fmt::Display + 'static {
    /// Associated primitive numeric type
    type Primitive: Primitive;

    /// A list of all flag variants in the enum
    const ITEMS: &'static [Self];

    /// Numeric representation of the variant
    fn bits(self) -> Self::Primitive;

    /// Flag value when no variants are set
    fn none() -> Flags<Self>;

    /// Flag value when all variants are set
    fn all() -> Flags<Self>;
}

/// Storage type for handling flags
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Flags<Enum, Primitive = <Enum as Flag>::Primitive> {
    val: Primitive,
    marker: std::marker::PhantomData<Enum>,
}

impl<Enum> std::fmt::Debug for Flags<Enum>
where
    Enum: Flag,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.val.fmt(f)
    }
}

impl<Enum> Default for Flags<Enum>
where
    Enum: Flag,
{
    fn default() -> Self {
        Self {
            val: <Enum as Flag>::Primitive::default(),
            marker: std::marker::PhantomData,
        }
    }
}

impl<Enum> Flags<Enum>
where
    Enum: Flag,
{
    /// Get a flag from a single enum value
    pub fn from_flag(flag: Enum) -> Self {
        Self {
            val: flag.bits(),
            marker: std::marker::PhantomData,
        }
    }

    /// Get a flag from a numeric value
    ///
    /// Note: the value is unchecked so any bit may be set. Be
    /// careful because `PartialEq` is a direct comparison of
    /// underlying bits.
    pub fn from_bits(bits: <Enum as Flag>::Primitive) -> Self {
        Self {
            val: bits,
            marker: std::marker::PhantomData,
        }
    }

    /// Numeric representation of the variant
    pub fn bits(&self) -> <Enum as Flag>::Primitive {
        self.val
    }

    /// Reference to numeric representation of the variant
    pub fn bits_ref(&self) -> &<Enum as Flag>::Primitive {
        &self.val
    }

    /// Check if at least one flag in common is set
    pub fn intersects<B: Into<Flags<Enum>>>(self, rhs: B) -> bool {
        (self & rhs.into()).bits() != Enum::none().bits()
    }

    /// Check if all flags provided in `rhs` are set
    pub fn contains<B: Into<Flags<Enum>>>(self, rhs: B) -> bool {
        let rhs = rhs.into();
        (self & rhs).bits() == rhs.bits()
    }

    pub fn is_empty(&self) -> bool {
        self.bits() == <Enum as Flag>::none().bits()
    }

    pub fn is_all(&self) -> bool {
        self.bits() == <Enum as Flag>::all().bits()
    }
}

impl<Enum: Flag> From<Enum> for Flags<Enum> {
    fn from(flag: Enum) -> Self {
        Self::from_flag(flag)
    }
}

impl<Enum: Flag> PartialEq<Enum> for Flags<Enum> {
    fn eq(&self, other: &Enum) -> bool {
        self.bits() == other.bits()
    }
}

impl<T, B> std::ops::BitOr<B> for Flags<T>
where
    T: Flag,
    B: Into<Flags<T>>,
{
    type Output = Flags<T>;
    fn bitor(self, other: B) -> Flags<T> {
        Flags::from_bits(self.bits() | other.into().bits())
    }
}

impl<T, B> std::ops::BitOrAssign<B> for Flags<T>
where
    T: Flag,
    B: Into<Flags<T>>,
{
    fn bitor_assign(&mut self, rhs: B) {
        *self = Flags::from_bits(self.bits() | rhs.into().bits())
    }
}

impl<T, B> std::ops::BitAnd<B> for Flags<T>
where
    T: Flag,
    B: Into<Flags<T>>,
{
    type Output = Flags<T>;
    fn bitand(self, other: B) -> Flags<T> {
        Flags::from_bits(self.bits() & other.into().bits())
    }
}

impl<T, B> std::ops::BitAndAssign<B> for Flags<T>
where
    T: Flag,
    B: Into<Flags<T>>,
{
    fn bitand_assign(&mut self, rhs: B) {
        *self = Flags::from_bits(self.bits() & rhs.into().bits())
    }
}

impl<T, B> std::ops::BitXor<B> for Flags<T>
where
    T: Flag,
    B: Into<Flags<T>>,
{
    type Output = Flags<T>;
    fn bitxor(self, other: B) -> Flags<T> {
        Flags::from_bits(self.bits() ^ other.into().bits())
    }
}

impl<T, B> std::ops::BitXorAssign<B> for Flags<T>
where
    T: Flag,
    B: Into<Flags<T>>,
{
    fn bitxor_assign(&mut self, rhs: B) {
        *self = Flags::from_bits(self.bits() ^ rhs.into().bits())
    }
}

impl<T: Flag> std::ops::Not for Flags<T> {
    type Output = Flags<T>;

    fn not(self) -> Self::Output {
        Flags::from_bits(!self.bits())
    }
}

impl<T: Flag> std::fmt::Display for Flags<T> {
    /// A pipe-separated list of set flags.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let none = self.bits() == T::none().bits();
        let mut first = true;
        for val in <T as Flag>::ITEMS
            .iter()
            .cloned()
            .filter(move |&flag| self.contains(flag))
        {
            write!(f, "{}{:?}", if first { "" } else { " | " }, val)?;
            first = false;

            if none {
                return Ok(());
            }
        }

        if none {
            write!(f, "NONE")?;
        }

        Ok(())
    }
}

impl<T: Flag> std::fmt::Binary for Flags<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Binary::fmt(&self.bits(), f)
    }
}

/// Example enum deriving `BitFlags`
pub mod example {
    use super::*;

    /// Example enum
    #[derive(Debug, Clone, Copy, PartialEq, Eq, BitFlags)]
    #[repr(u8)]
    pub enum Test {
        A = 0b0001,
        B = 0b0010,
        C = 0b0100,
        D = 0b1000,
        /// Variants can be bitmask of other fields
        E = Test::A as u8 | Test::B as u8 | Test::C as u8 | Test::D as u8,
    }
}

#[cfg(test)]
mod test {
    use super::{example::*, *};

    #[test]
    fn test_enum_bits() {
        let bits = 0b1010_1010;
        let flags = Flags::<Test>::from_bits(bits);
        assert_eq!(bits, flags.bits());
        assert_eq!(&bits, flags.bits_ref());
    }

    #[test]
    fn test_enum_or() {
        let mut flags = Test::A | Test::B;
        assert_eq!(0b0011, flags.bits());

        flags |= Test::C;
        assert_eq!(0b0111, flags.bits());

        flags |= Test::C | Test::D;
        assert_eq!(0b1111, flags.bits());
    }

    #[test]
    fn test_enum_and() {
        let mut flags = Test::E & Test::B;
        assert_eq!(0b0010, flags.bits());

        flags &= Test::B;
        assert_eq!(0b0010, flags.bits());

        flags &= Test::E & Test::B;
        assert_eq!(0b0010, flags.bits());
    }

    #[test]
    fn test_enum_xor() {
        let mut flags = Test::A ^ Test::B;
        assert_eq!(0b0011, flags.bits());

        flags ^= Test::C;
        assert_eq!(0b0111, flags.bits());

        flags ^= Test::D ^ Test::B;
        assert_eq!(0b1101, flags.bits());
    }

    #[test]
    fn test_enum_not() {
        let flags = !Test::A;
        assert_eq!(0b1111_1110, flags.bits());
        let flags = !(Test::A ^ Test::B);
        assert_eq!(0b1111_1100, flags.bits());
    }

    #[test]
    fn test_contains() {
        let flags = Test::A | Test::C;
        assert!(flags.contains(Test::A));
        assert!(!flags.contains(Test::B));
        assert!(!flags.contains(Test::E));
        assert!(!flags.contains(Test::B | Test::D));
        assert!(!flags.contains(Test::A | Test::B));
        assert!(flags.contains(Test::A | Test::C));
    }

    #[test]
    fn test_intersects() {
        let flags = Test::A | Test::C;
        assert!(flags.intersects(Test::A));
        assert!(flags.intersects(Test::E));
        assert!(flags.intersects(Test::A | Test::B));
        assert!(flags.intersects(Test::A | Test::C));
        assert!(flags.intersects(Test::A | Test::B | Test::C));
        assert!(!flags.intersects(Test::B | Test::D));
    }

    #[test]
    fn test_eq() {
        let flags = Test::A;
        assert_eq!(flags, Test::A);
        assert_eq!(Test::A, flags);

        let flags = Test::A | Test::C;
        assert_ne!(flags, Test::A);
        assert_ne!(flags, Test::C);
        assert_ne!(Test::A, flags);
        assert_eq!(flags, Test::A | Test::C);
        assert_ne!(flags, Test::A | Test::C | Test::E);

        let flags = Flags::<Test>::from_bits(0b1000_0001);
        assert_ne!(flags, Test::A);
    }

    #[test]
    fn test_enum_string() {
        assert_eq!("NONE", Test::none().to_string());
        assert_eq!("A", Test::A.to_string());
        assert_eq!("A | B", (Test::A | Test::B).to_string());
        assert_eq!("A | B | C | D | E", Test::E.to_string());
        assert_eq!("A | B | C | D | E", Flags::from_flag(Test::E).to_string());
    }

    #[test]
    fn test_enum_string_none() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, BitFlags)]
        #[repr(u8)]
        pub enum Test {
            Zero = 0b0000,
            A = 0b0001,
            B = 0b0010,
            C = 0b0100,
            D = 0b1000,
            /// Variants can be bitmask of other fields
            E = Test::A as u8 | Test::B as u8 | Test::C as u8 | Test::D as u8,
        }
        assert_eq!("Zero", Test::Zero.to_string());
        assert_eq!("Zero", Test::none().to_string());
        assert_eq!("Zero", Flags::from_flag(Test::Zero).to_string());
    }

    #[test]
    fn test_enum_format() {
        assert_eq!("A", format!("{:?}", Test::A));
        assert_eq!("E", format!("{:?}", Test::E));
        assert_eq!("0", format!("{:?}", Test::none()));

        assert_eq!("0", format!("{:b}", Test::none()));
        assert_eq!("1", format!("{:b}", Test::A));
        assert_eq!("1111", format!("{:b}", Test::E));
    }

    #[test]
    fn test_enum_from_str() {
        use std::str::FromStr;
        assert_eq!(Err(()), Test::from_str(""));
        assert_eq!(Ok(Test::A), Test::from_str("a"));
        assert_eq!(Ok(Test::A), Test::from_str("A"));
    }

    #[test]
    fn test_all() {
        assert_eq!(Test::E, Test::all());
        assert!(!Flags::from_flag(Test::A).is_all());
        assert!(Flags::from_flag(Test::E).is_all());
    }

    #[test]
    fn test_none() {
        assert_eq!(Flags::from_bits(0), Test::none());
        assert!(Flags::<Test>::from_bits(0).is_empty());
        assert!(!Flags::from_flag(Test::A).is_empty());
        assert!(!Flags::from_flag(Test::E).is_empty());
    }
}
