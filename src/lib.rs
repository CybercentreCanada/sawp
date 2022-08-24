/*!
# SAWP: Security Aware Wire Protocol parsing library

This library contains parsers for various wire protocols
and is intended to be used in network security sensors.

The base library contains all of the common types and traits
used by the parsers.

Usage documentation can be found in the [README](https://github.com/CybercentreCanada/sawp/blob/main/README.md).

## Protocols

Each protocol, along with certain features, are implemented
in a separate package inside this workspace. This reduces the
number dependencies needed for using various protocols or
features. A practical use of this library can be found by
referring to the protocol parser you wish to use:
- [Diameter](/sawp-diameter)
- [Json](/sawp-json)
- [Modbus](/sawp-modbus)

## Utility

The following utility packages also exist:
- [File](/sawp-file) Serializes API calls for debugging
*/

#![allow(clippy::unneeded_field_pattern)]

/// Return common errors
pub mod error;

/// Parse Messages
pub mod parser;

/// Probe Bytes
pub mod probe;

/// Describe a Protocol
pub mod protocol;

#[cfg(feature = "ffi")]
pub mod ffi;
