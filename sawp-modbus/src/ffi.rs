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
pub unsafe extern "C" fn sawp_modbus_create() -> *mut Modbus {
    let parser = Modbus {};
    parser.into_ffi_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_destroy(d: *mut Modbus) {
    if !d.is_null() {
        // d will be dropped when this box goes out of scope
        Box::from_raw(d);
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
                Box::from_raw(self.error);
            }
        }
    }
}

/// Free ParseResult
/// Will also destroy contained message and error
#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_parse_result_destroy(d: *mut ParseResult) {
    if !d.is_null() {
        // d will be dropped when this box goes out of scope
        Box::from_raw(d);
    }
}

#[no_mangle]
pub unsafe extern "C" fn sawp_modbus_message_destroy(d: *mut Message) {
    if !d.is_null() {
        // d will be dropped when this box goes out of scope
        Box::from_raw(d);
    }
}

/* ---- AccessType Flags ---- */
pub const ACCESSTYPE_NONE: u8 = 0b0000_0000;
pub const ACCESSTYPE_READ: u8 = 0b0000_0001;
pub const ACCESSTYPE_WRITE: u8 = 0b0000_0010;
pub const ACCESSTYPE_DISCRETES: u8 = 0b0000_0100;
pub const ACCESSTYPE_COILS: u8 = 0b0000_1000;
pub const ACCESSTYPE_INPUT: u8 = 0b0001_0000;
pub const ACCESSTYPE_HOLDING: u8 = 0b0010_0000;
pub const ACCESSTYPE_SINGLE: u8 = 0b0100_0000;
pub const ACCESSTYPE_MULTIPLE: u8 = 0b1000_0000;
pub const ACCESSTYPE_BIT_ACCESS_MASK: u8 = 0b0000_1100;
pub const ACCESSTYPE_FUNC_MASK: u8 = 0b0011_1100;
pub const ACCESSTYPE_WRITE_SINGLE: u8 = 0b0100_0010;
pub const ACCESSTYPE_WRITE_MULTIPLE: u8 = 0b1000_0010;

/* ---- CodeCategory Flags ---- */
pub const CODECATEGORY_NONE: u8 = 0b0000_0000;
pub const CODECATEGORY_PUBLIC_ASSIGNED: u8 = 0b0000_0001;
pub const CODECATEGORY_PUBLIC_UNASSIGNED: u8 = 0b0000_0010;
pub const CODECATEGORY_USER_DEFINED: u8 = 0b0000_0100;
pub const CODECATEGORY_RESERVED: u8 = 0b0000_1000;

/* ---- ErrorFlags Flags ---- */
pub const ERRORFLAGS_NONE: u8 = 0b0000_0000;
pub const ERRORFLAGS_DATA_VALUE: u8 = 0b0000_0001;
pub const ERRORFLAGS_DATA_LENGTH: u8 = 0b0000_0010;
pub const ERRORFLAGS_EXC_CODE: u8 = 0b0000_0100;
pub const ERRORFLAGS_FUNC_CODE: u8 = 0b0000_1000;
pub const ERRORFLAGS_PROTO_ID: u8 = 0b0001_0000;
