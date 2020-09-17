#![no_main]
use libfuzzer_sys::fuzz_target;

use sawp_modbus::Modbus;
use sawp::parser::Parse;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = Modbus::parse(data) {
        eprintln!("Modbus: Error parsing {:?}", e);
    }
});
