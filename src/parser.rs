use crate::error::Result;
use crate::protocol::Protocol;

/// Destination of the input byte stream.
#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    /// Message is destined to the client
    ToClient,
    /// Message is destined to the server
    ToServer,
    /// Direction is not known
    Unknown,
}

/// Trait for parsing message from an input byte stream.
pub trait Parse<'a>: Protocol<'a> {
    /// Returns a tuple containing the remaining unparsed data and the parsed `Message`.
    ///
    /// A return value of `Result::Ok` indicates that the parser has *made progress*
    /// and should only be used when the remaining unparsed data is less than the input.
    ///
    /// A return value of `Result::Err` indicates that *no progress* was made
    /// and the user may call the parse function again with the same input in
    /// some scenarios:
    /// - `ErrorKind::Incomplete`: call `parse` once more input data is available.
    ///
    /// Consequently, `Result::Ok(None)` is used to indicate the parser made
    /// progress but needs more data to return a complete `Message`. Internal
    /// buffering may occur depending on the implementation.
    ///
    /// `Result::Err(ErrorKind::Incomplete(_))` must be used instead of `Result::Ok(None)`
    /// when no progress was made parsing the input.
    fn parse(
        &self,
        input: &'a [u8],
        direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)>;
}
