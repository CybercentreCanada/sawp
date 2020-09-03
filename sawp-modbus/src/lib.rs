use sawp::error::{Error, ErrorKind, Result};
use sawp::parser::Parse;
use sawp::protocol::Protocol;

#[derive(Debug)]
pub struct Modbus {}

#[derive(Debug, PartialEq)]
pub struct Message {}

impl Protocol for Modbus {
    type Message = Message;

    fn name() -> &'static str {
        "modbus"
    }
}

impl Parse for Modbus {
    fn parse(_input: &[u8]) -> Result<(usize, Self::Message)> {
        Err(Error::new(ErrorKind::Unimplemented))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error::{Error, ErrorKind, Result};

    #[rstest(
        input,
        expected,
        case(b"", Err(Error::new(ErrorKind::Unimplemented))),
        case(b"hello world", Err(Error::new(ErrorKind::Unimplemented)))
    )]
    #[test]
    fn test_modbus(input: &[u8], expected: Result<(usize, <Modbus as Protocol>::Message)>) {
        assert_eq!(Modbus::parse(input), expected);
    }
}
