#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

use std::num::NonZeroUsize;

// Re-export types used for ErrorKind
use nom::error::ErrorKind as NomErrorKind;
use nom::Needed as NomNeeded;

/// Helper that uses this module's error type
pub type Result<T> = std::result::Result<T, Error>;

/// Helper for nom's default error type
pub type NomError<I> = nom::error::Error<I>;

/// Common protocol or parsing error
///
/// This error type is meant to return the errors that
/// are common across parsers and other sub packages.
/// Sub packages may choose to implement their own error
/// types if they wish to avoid adding extra dependencies
/// to the base crate.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp"))]
pub struct Error {
    pub kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// Helper for creating an error with a `ErrorKind::Incomplete` and a needed size.
    pub fn incomplete_needed(size: usize) -> Self {
        Error::new(ErrorKind::Incomplete(
            NonZeroUsize::new(size)
                .map(Needed::Size)
                .unwrap_or(Needed::Unknown),
        ))
    }

    /// Helper for creating an error with a `ErrorKind::Incomplete` and an unknown size.
    pub fn incomplete() -> Self {
        Error::new(ErrorKind::Incomplete(Needed::Unknown))
    }

    /// Helper for creating a parse error.
    #[cfg(verbose)]
    pub fn parse(msg: Option<String>) -> Self {
        Error::new(ErrorKind::ParseError(msg))
    }

    /// Helper for creating a parse error.
    #[cfg(not(verbose))]
    pub fn parse(_msg: Option<String>) -> Self {
        Error::new(ErrorKind::ParseError(None))
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

/// Number of bytes needed for the next parsing attempt.
///
/// Used in `ErrorKind::Incomplete` to tell the caller how many bytes to wait
/// for before calling the parser with more data.
#[derive(Debug, PartialEq)]
pub enum Needed {
    Unknown,
    Size(NonZeroUsize),
}

/// Kinds of common errors used by the parsers
#[derive(Debug, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(type_only, prefix = "sawp"))]
pub enum ErrorKind {
    /// Feature is not yet implemented.
    Unimplemented,
    /// Parser could not advance based on the data provided.
    ///
    /// Usually indicates the provided input bytes cannot be parsed
    /// for the protocol.
    //
    // Developer note:
    //
    // This error should only be used as a last resort. Consider
    // returning Ok and adding validation error flags to the
    // parser's `Message` instead.
    InvalidData,
    /// Generic parsing error with optional message.
    ParseError(Option<String>),
    /// Parser did not advance because more data is required to
    /// make a decision.
    ///
    /// The caller should gather more data and try again.
    Incomplete(Needed),
}

impl From<NomErrorKind> for ErrorKind {
    #[cfg(verbose)]
    fn from(kind: NomErrorKind) -> Self {
        Self::ParseError(Some(format!("{:?}", kind)))
    }

    #[cfg(not(verbose))]
    fn from(_kind: NomErrorKind) -> Self {
        Self::ParseError(None)
    }
}

impl<I: std::fmt::Debug> From<nom::Err<NomError<I>>> for Error {
    fn from(nom_err: nom::Err<NomError<I>>) -> Self {
        match nom_err {
            nom::Err::Error(err) | nom::Err::Failure(err) => Error::new(err.code.into()),
            nom::Err::Incomplete(needed) => match needed {
                NomNeeded::Unknown => Error::incomplete(),
                NomNeeded::Size(size) => Error::incomplete_needed(size.into()),
            },
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match &self.kind {
            ErrorKind::Unimplemented => write!(f, "Unimplemented feature"),
            ErrorKind::InvalidData => write!(f, "Encountered invalid data"),
            ErrorKind::ParseError(err) if err.is_some() => {
                write!(f, "Parsing error: {}", err.clone().unwrap())
            }
            ErrorKind::ParseError(_) => write!(f, "Parsing error"),
            ErrorKind::Incomplete(Needed::Unknown) => write!(f, "More bytes required to parse"),
            ErrorKind::Incomplete(Needed::Size(n)) => {
                write!(f, "{} more bytes required to parse", n)
            }
        }
    }
}

impl std::error::Error for Error {}

impl<I: std::fmt::Debug> From<NomError<I>> for Error {
    fn from(nom_err: NomError<I>) -> Self {
        Error::new(nom_err.code.into())
    }
}
