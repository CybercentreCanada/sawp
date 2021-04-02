//! SAWP File Format
//!
//! This module defines structs to serialize and deserialize arguments to SAWP
//! calls in order to replay them into a parser.

#![allow(clippy::upper_case_acronyms)]

extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate rmp_serde as rmps;

pub mod error;
pub mod format;

pub type Version = usize;

/// Get the version number of the format
pub fn version() -> Version {
    // This should never fail because the compiler sets the environment variable.
    // There doesn't seem to be a "const fn" version of the parse function.
    env!("CARGO_PKG_VERSION_MAJOR")
        .parse()
        .expect("failed to parse version number")
}
