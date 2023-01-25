use sawp::protocol::Protocol;
use sawp_ike::*;

#[test]
fn test_name() {
    assert_eq!(Ike::name(), "ike");
}
