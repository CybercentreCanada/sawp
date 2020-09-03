use crate::error::Result;
use crate::protocol::Protocol;

pub trait Parse: Protocol {
    /// Parse a chunk of bytes into the protocol's Message type.
    ///
    /// Returns a tuple with the number of bytes parsed from the input and the
    /// parsed message.
    fn parse(input: &[u8]) -> Result<(usize, Self::Message)>;
}
