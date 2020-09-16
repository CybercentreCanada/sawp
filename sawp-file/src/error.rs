use crate::Version;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum ErrorKind {
    IOError(std::io::Error),
    Serialization(String),
    // Failed to parse version string to integer.
    VersionParse,
    // Version did not match during deserialization (expected, actual).
    VersionMismatch((Version, Version)),
}
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match &self.kind {
            ErrorKind::IOError(err) => write!(fmt, "io error: {}", err),
            ErrorKind::Serialization(err) => write!(fmt, "serialization error: {}", err),
            ErrorKind::VersionParse => write!(fmt, "failed to parse version"),
            ErrorKind::VersionMismatch((expected, actual)) => {
                write!(fmt, "expected version {} got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(other: std::io::Error) -> Self {
        Self::new(ErrorKind::IOError(other))
    }
}

impl std::convert::From<rmps::encode::Error> for Error {
    fn from(other: rmps::encode::Error) -> Self {
        Error::new(ErrorKind::Serialization(other.to_string()))
    }
}

impl std::convert::From<rmps::decode::Error> for Error {
    fn from(other: rmps::decode::Error) -> Self {
        Error::new(ErrorKind::Serialization(other.to_string()))
    }
}
