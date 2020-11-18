/// Represents the basic elements of a protocol
pub trait Protocol<'a> {
    /// Type of message returned when parsing
    type Message: 'a;

    /// Protocol name string
    fn name() -> &'static str;
}
