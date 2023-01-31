#![allow(dead_code)]

use super::{payloads::Attribute, Direction, Ike, Message};

use sawp::{error::Error, parser::Parse};

use sawp_ffi::IntoFFIPtr;

#[repr(C)]
pub struct ParseResult {
    message: *mut Message,
    size_read: usize,
    error: *mut Error,
}

#[no_mangle]
pub unsafe extern "C" fn sawp_ike_create() -> *mut Ike {
    let parser = Ike::default();
    parser.into_ffi_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sawp_ike_destroy(d: *mut Ike) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_ike_parse(
    parser: *const Ike,
    direction: Direction,
    data: *const u8,
    length: usize,
) -> *mut ParseResult {
    let input = std::slice::from_raw_parts(data, length);
    match (*parser).parse(input, direction) {
        Ok((sl, message)) => ParseResult {
            message: message.into_ffi_ptr(),
            // Should never actually underflow as parse cannot grow the input slice
            size_read: length.saturating_sub(sl.len()),
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
            sawp_ike_message_destroy(self.message);
            if !self.error.is_null() {
                drop(Box::from_raw(self.error));
            }
        }
    }
}

/// Free ParseResult
/// Will also destroy contained message and error
#[no_mangle]
pub unsafe extern "C" fn sawp_ike_parse_result_destroy(d: *mut ParseResult) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}

#[no_mangle]
pub unsafe extern "C" fn sawp_ike_message_destroy(d: *mut Message) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}

#[no_mangle]
pub unsafe extern "C" fn sawp_ike_vec_attributes_ptr_to_idx(
    #[allow(clippy::ptr_arg)] vec: &Vec<Attribute>,
    n: usize,
) -> *const Attribute {
    vec.get(n).unwrap()
}

#[no_mangle]
pub unsafe extern "C" fn sawp_ike_vec_attributes_get_size(
    #[allow(clippy::ptr_arg)] vec: &Vec<Attribute>,
) -> usize {
    vec.len()
}

#[no_mangle]
pub unsafe extern "C" fn sawp_ike_2d_vec_ptr_to_idx(
    #[allow(clippy::ptr_arg)] vec: &Vec<Vec<u8>>,
    n: usize,
) -> *const Vec<u8> {
    vec.get(n).unwrap()
}

#[no_mangle]
pub unsafe extern "C" fn sawp_ike_2d_vec_get_size(
    #[allow(clippy::ptr_arg)] vec: &Vec<Vec<u8>>,
) -> usize {
    vec.len()
}

#[cfg(test)]
mod tests {
    use super::{super::payloads::AttributeFormat, *};

    #[test]
    fn atttribute_array() {
        let vec = vec![
            Attribute {
                att_format: AttributeFormat::TypeLengthValue,
                att_type: 1,
                att_length: 3,
                att_value: vec![1, 2, 3],
            },
            Attribute {
                att_format: AttributeFormat::TypeValue,
                att_type: 2,
                att_length: 0,
                att_value: vec![1, 2],
            },
        ];

        assert_eq!(unsafe { sawp_ike_vec_attributes_get_size(&vec) }, 2);
        let vec_ptr = unsafe { sawp_ike_vec_attributes_ptr_to_idx(&vec, 0) };
        assert_eq!(
            unsafe { &*vec_ptr },
            &Attribute {
                att_format: AttributeFormat::TypeLengthValue,
                att_type: 1,
                att_length: 3,
                att_value: vec![1, 2, 3]
            }
        );

        let vec_ptr = unsafe { sawp_ike_vec_attributes_ptr_to_idx(&vec, 1) };
        assert_eq!(
            unsafe { &*vec_ptr },
            &Attribute {
                att_format: AttributeFormat::TypeValue,
                att_type: 2,
                att_length: 0,
                att_value: vec![1, 2],
            }
        );
    }

    #[test]
    fn two_d_array() {
        let vec = vec![vec![1u8, 2u8], vec![3u8, 4u8]];

        assert_eq!(unsafe { sawp_ike_2d_vec_get_size(&vec) }, 2);

        let vec_ptr = unsafe { sawp_ike_2d_vec_ptr_to_idx(&vec, 0) };
        assert_eq!(unsafe { &*vec_ptr }, &vec![1u8, 2u8]);
        let vec_ptr = unsafe { sawp_ike_2d_vec_ptr_to_idx(&vec, 1) };
        assert_eq!(unsafe { &*vec_ptr }, &vec![3u8, 4u8]);
    }
}
