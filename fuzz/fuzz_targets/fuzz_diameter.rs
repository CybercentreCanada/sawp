#![no_main]
use libfuzzer_sys::fuzz_target;

use sawp_diameter::Diameter;
use sawp::parser::{Parse, Direction};

fuzz_target!(|data: &[u8]| {
    let parser = Diameter {};
    if let Err(e) = parser.parse(data, Direction::Unknown) {
        eprintln!("Diameter: Error parsing {:?}", e);
    }
});
