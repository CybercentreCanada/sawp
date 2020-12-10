use crate::error::{Error, ErrorKind};
use crate::parser::{Direction, Parse};
use crate::protocol::Protocol;

/// Result of probing the underlying bytes.
#[derive(Debug, PartialEq)]
pub enum Status {
    /// Data matches this protocol
    Recognized,
    /// Data does not match this protocol
    Unrecognized,
    /// More data is needed to make a decision
    Incomplete,
}

pub trait Probe<'a>: Protocol<'a> + Parse<'a> {
    /// Probes the input to recognize if the underlying bytes likely match this
    /// protocol.
    ///
    /// Returns a probe status. Probe again once more data is available when the
    /// status is `Status::Incomplete`.
    fn probe(&self, input: &'a [u8], direction: Direction) -> Status {
        match self.parse(input, direction) {
            Ok((_, _)) => Status::Recognized,
            Err(Error {
                kind: ErrorKind::Incomplete(_),
            }) => Status::Incomplete,
            Err(_) => Status::Unrecognized,
        }
    }
}
