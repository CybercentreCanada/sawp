#![no_main]
use libfuzzer_sys::fuzz_target;

use sawp_modbus::Modbus;
use sawp::parser::{Parse, Direction};

fuzz_target!(|data: &[u8]| {
    let parser = Modbus::default();
    if let Err(e) = parser.parse(data, Direction::Unknown) {
        eprintln!("Modbus: Error parsing {:?}", e);
    }
});
