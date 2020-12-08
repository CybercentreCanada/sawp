#![no_main]
use libfuzzer_sys::fuzz_target;

use sawp_diameter::Diameter;
use sawp::parser::Parse;

fuzz_target!(|data: &[u8]| {
    let modbus = Diameter {};
    if let Err(e) = modbus.parse(data) {
        eprintln!("Diameter: Error parsing {:?}", e);
    }
});
