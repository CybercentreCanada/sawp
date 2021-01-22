/// Helper that uses this module's error type
pub type Result<T> = std::result::Result<T, Error>;

/// Helper for nom's default error type
// A better nom error will be available once we can migrate
// to nom 6.0+
pub type NomError<I> = (I, nom::error::ErrorKind);

/// Common protocol or parsing error
///
/// This error type is meant to return the errors that
/// are common across parsers and other sub packages.
/// Sub packages may choose to implement their own error
/// types if they wish to avoid adding extra dependencies
/// to the base crate.
#[derive(Debug, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

/// Kinds of common errors used by the parsers
#[derive(Debug, PartialEq)]
#[non_exhaustive]
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
    /// Generic nom parsing error.
    Nom(nom::error::ErrorKind),
    /// Parser did not advance because more data is required to
    /// make a decision.
    ///
    /// The caller should gather more data and try again.
    Incomplete(nom::Needed),
}

impl<I: std::fmt::Debug> From<nom::Err<NomError<I>>> for Error {
    fn from(nom_err: nom::Err<NomError<I>>) -> Self {
        match nom_err {
            nom::Err::Error(err) | nom::Err::Failure(err) => Error::new(ErrorKind::Nom(err.1)),
            nom::Err::Incomplete(size) => Error::new(ErrorKind::Incomplete(size)),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        todo!()
    }
}

impl std::error::Error for Error {}
