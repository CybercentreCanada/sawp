//! Format Specification
//!
//! The format for serializing SAWP API Calls is a series of consecutive
//! self-contained messages.
//!
//! The messages are of the following msgpack type where `N` is the total number
//! messages ranging from two to infinity.
//!
//! | message | type  | description           |
//! |---------|-------|-----------------------|
//! | 1       | int   | version number        |
//! | 2..N    | call  | call structure fields |
//!
//! Calls are stored in seperate messages to allow for a streaming format. Users
//! _do not_ have to store the entire SAWP "file" into memory. Messages can be
//! parsed asynchronously.
//!
//! This format is subject to change and other applications should not attempt
//! to parse it. Use this library instead for encoding and decoding instead.

use crate::error::{Error, ErrorKind, Result};
use crate::Version;
use std::io::{Read, Write};

// Direction of a chunk of data or gap.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Copy, Clone)]
pub enum Direction {
    Unknown,
    ToServer,
    ToClient,
}

/// A chunk of input data to parse.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Data {
    direction: Direction,
    data: Vec<u8>,
}

/// Identifies a missing chunk of input data.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Gap {
    direction: Direction,
    gap: usize,
}

/// A list of all API calls we want to expose.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Call {
    /// Parse the input data.
    Parse(Data),
    /// Identify a gap.
    Gap(Gap),
}

/// Reads the expected format from a source.
pub struct Reader<R: Read> {
    inner: R,
}

impl<R: Read> Reader<R> {
    /// Creates a new reader.
    ///
    /// This will fail if the version in the format doesn't match the current
    /// version of this module.
    pub fn new(inner: R) -> Result<Self> {
        let mut reader = Reader { inner };
        let expected_version = crate::version();
        let actual_version: Version = rmp_serde::from_read(&mut reader.inner)?;
        if expected_version != actual_version {
            return Err(Error::new(ErrorKind::VersionMismatch((
                expected_version,
                actual_version,
            ))));
        }
        Ok(reader)
    }
}

impl<R: Read> std::iter::Iterator for Reader<R> {
    type Item = Call;

    fn next(&mut self) -> Option<Self::Item> {
        rmp_serde::from_read(&mut self.inner).ok()
    }
}

/// Writes serialized API calls to a sink.
pub struct Writer<W: Write> {
    inner: W,
}

impl<W: Write> Writer<W> {
    /// Creates a writer.
    pub fn new(inner: W) -> Result<Self> {
        let mut writer = Writer { inner };
        writer.version()?;
        Ok(writer)
    }

    /// Writes the format version number.
    fn version(&mut self) -> Result<()> {
        let bytes = rmp_serde::to_vec(&crate::version())?;
        self.inner.write_all(&bytes)?;
        Ok(())
    }

    /// Writes the parse API call.
    pub fn parse(&mut self, direction: Direction, data: &[u8]) -> Result<()> {
        let call = Call::Parse(Data {
            direction,
            data: data.to_vec(),
        });
        let bytes = rmp_serde::to_vec(&call)?;
        self.inner.write_all(&bytes)?;
        Ok(())
    }

    /// Writes the gap API call.
    pub fn gap(&mut self, direction: Direction, gap: usize) -> Result<()> {
        let call = Call::Gap(Gap { direction, gap });
        let bytes = rmp_serde::to_vec(&call)?;
        self.inner.write_all(&bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write() {
        let data = b"GET /index.php HTTP/1.1\r\n\r\n";
        let gap = 10;

        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer).expect("failed to create writer");
        writer.parse(Direction::ToServer, data).unwrap();
        writer.gap(Direction::ToServer, gap).unwrap();

        let buffer = std::io::Cursor::new(buffer);
        let reader = Reader::new(buffer).expect("failed to create reader");
        let result: Vec<Call> = reader.collect();
        let expected: Vec<Call> = vec![
            Call::Parse(Data {
                direction: Direction::ToServer,
                data: data.to_vec(),
            }),
            Call::Gap(Gap {
                direction: Direction::ToServer,
                gap,
            }),
        ];
        assert_eq!(expected, result);
    }

    #[should_panic(expected = "VersionMismatch")]
    #[test]
    fn test_version_mismatch() {
        // Test a version number that is off by one
        let wrong_version = crate::version() + 1;
        let bytes = rmp_serde::to_vec(&wrong_version).unwrap();
        let buffer = std::io::Cursor::new(bytes);
        let _ = Reader::new(buffer).unwrap();
    }

    #[test]
    fn test_corrupt_bytes() {
        let data = b"GET /index.php HTTP/1.1\r\n\r\n";
        let gap = 10;

        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer).expect("failed to create writer");
        writer.parse(Direction::ToServer, data).unwrap();
        writer.gap(Direction::ToServer, gap).unwrap();

        // Process everything but the last byte.
        let buffer = std::io::Cursor::new(&buffer[..buffer.len() - 1]);
        let reader = Reader::new(buffer).expect("failed to create reader");

        // Errors are ignored and the iterator will end prematurely
        assert_eq!(reader.count(), 1);
    }
}
