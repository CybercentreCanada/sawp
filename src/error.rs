pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    Unimplemented,
    InvalidData,
    Nom(nom::error::ErrorKind),
    Incomplete(nom::Needed),
}

impl<I: std::fmt::Debug> From<nom::Err<(I, nom::error::ErrorKind)>> for Error {
    fn from(nom_err: nom::Err<(I, nom::error::ErrorKind)>) -> Self {
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
