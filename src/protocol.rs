/// Represents the basic elements of a protocol
pub trait Protocol {
    /// Type of message returned when parsing
    type Message;

    /// Protocol name string
    fn name() -> &'static str;
}
