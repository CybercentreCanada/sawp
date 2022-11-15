#![allow(dead_code)]
use super::*;
use sawp::error::Error;
use sawp::parser::Parse;
use sawp_ffi::*;

#[repr(C)]
pub struct ParseResult {
    message: *mut Message,
    size_read: usize,
    error: *mut Error,
}

#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_create(probe_strict: bool) -> *mut Modbus {
    let parser = Modbus { probe_strict };
    parser.into_ffi_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_destroy(d: *mut Modbus) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_parse(
    parser: *const Modbus,
    direction: Direction,
    data: *const u8,
    length: usize,
) -> *mut ParseResult {
    let input = std::slice::from_raw_parts(data, length);
    match (*parser).parse(input, direction) {
        Ok((sl, message)) => ParseResult {
            message: message.into_ffi_ptr(),
            size_read: length - sl.len(),
            error: std::ptr::null_mut(),
        }
        .into_ffi_ptr(),
        Err(e) => ParseResult {
            message: std::ptr::null_mut(),
            size_read: 0,
            error: e.into_ffi_ptr(),
        }
        .into_ffi_ptr(),
    }
}

impl Drop for ParseResult {
    fn drop(&mut self) {
        unsafe {
            sawp_modbus_message_destroy(self.message);
            if !self.error.is_null() {
                drop(Box::from_raw(self.error));
            }
        }
    }
}

/// Free ParseResult
/// Will also destroy contained message and error
#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_parse_result_destroy(d: *mut ParseResult) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}

#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_message_destroy(d: *mut Message) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}
