//! SAWP JSON Parser

#![allow(clippy::unneeded_field_pattern)]

use sawp::error::{Error, ErrorKind, Result};
use sawp::parser::{Direction, Parse};
use sawp::probe::Probe;
use sawp::protocol::Protocol;
use serde_json::{Deserializer, Value};

#[derive(Debug)]
pub struct Json {}

#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub value: Value,
}

impl Message {
    pub fn new(value: Value) -> Self {
        Self { value }
    }
}

impl Protocol<'_> for Json {
    type Message = Message;

    fn name() -> &'static str {
        "json"
    }
}

impl<'a> Parse<'a> for Json {
    type State = ();
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
        _state: &mut Self::State,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let mut stream = Deserializer::from_slice(input).into_iter::<Value>();

        match stream.next() {
            Some(Ok(value)) => Ok((&input[stream.byte_offset()..], Some(Message::new(value)))),
            Some(Err(e)) if e.is_eof() => Err(Error::incomplete()),
            _ => Err(Error::new(ErrorKind::InvalidData)),
        }
    }
}

impl<'a> Probe<'a> for Json {}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error::{Error, ErrorKind, Needed, Result};
    use sawp::probe::Status;
    use serde_json::json;

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(Error::new(ErrorKind::InvalidData))),
        case::singlequote(b"''", Err(Error::new(ErrorKind::InvalidData))),
        case::incomplete(b"{\"a\":", Err(Error::new(ErrorKind::Incomplete(Needed::Unknown)))),

        // Smoke tests
        case::number(b"1234", Ok((0, Some(Message::new(json!(1234)))))),
        case::null(b"null", Ok((0, Some(Message::new(json!(null)))))),
        case::bool_true(b"true", Ok((0, Some(Message::new(json!(true)))))),
        case::bool_false(b"false", Ok((0, Some(Message::new(json!(false)))))),
        case::empty_obj(b"{}", Ok((0, Some(Message::new(json!({})))))),
        case::empty_list(b"[]", Ok((0, Some(Message::new(json!([])))))),
        case::empty_string(b"\"\"", Ok((0, Some(Message::new(json!("")))))),
        case::object(b"{\"a\":\"b\"}", Ok((0, Some(Message::new(json!({"a": "b"})))))),
        case::list(b"[\"a\", \"b\"]", Ok((0, Some(Message::new(json!(["a", "b"])))))),
        case::whitespace(b"\n\t{\n\r\n\"a\":    \t\"b\"\n}", Ok((0, Some(Message::new(json!({"a": "b"})))))),
        case::multi(b"{}[1]", Ok((3, Some(Message::new(json!({})))))),
    )]
    fn parse(input: &[u8], expected: Result<(usize, Option<<Json as Protocol>::Message>)>) {
        let json = Json {};
        assert_eq!(
            expected,
            json.parse(input, Direction::Unknown, &mut ())
                .map(|(left, msg)| (left.len(), msg)),
        );
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Status::Unrecognized),
        case::incomplete(b"{\"a\":", Status::Incomplete),
        case::number(b"1234", Status::Recognized)
    )]
    fn probe(input: &[u8], expected: Status) {
        let json = Json {};
        assert_eq!(expected, json.probe(input, Direction::Unknown));
    }

    #[test]
    fn regression_truncated_json_incomplete() {
        // Truncated-but-valid JSON fragments must surface as Incomplete (not
        // InvalidData) so streaming callers/Probe buffer more bytes instead of
        // rejecting the protocol and allowing fragmentation evasion.
        let json = Json {};
        for frag in [
            &b"{\"cmd\":\"rev"[..],
            &b"{\"a\":"[..],
            &b"["[..],
            &b"[1,"[..],
            &b"\"unterminated"[..],
        ] {
            assert_eq!(
                Err(Error::new(ErrorKind::Incomplete(Needed::Unknown))),
                json.parse(frag, Direction::Unknown, &mut ()),
            );
            assert_eq!(Status::Incomplete, json.probe(frag, Direction::Unknown));
        }

        // Genuinely malformed input must still be reported as InvalidData.
        assert_eq!(
            Err(Error::new(ErrorKind::InvalidData)),
            json.parse(b"''", Direction::Unknown, &mut ()),
        );
    }
}
