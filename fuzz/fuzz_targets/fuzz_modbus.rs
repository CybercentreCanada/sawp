#![no_main]
use libfuzzer_sys::fuzz_target;

use sawp_modbus::Modbus;
use sawp::parser::Parse;

fuzz_target!(|data: &[u8]| {
    let modbus = Modbus {};
    if let Err(e) = modbus.parse(data) {
        eprintln!("Modbus: Error parsing {:?}", e);
    }
});
