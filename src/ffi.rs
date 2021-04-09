use sawp_ffi::deref;

/// Note this function only works for Vec<u8>
/// for other types, use the field_ptr accessor
/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_vector_get_data(vec: *const Vec<u8>) -> *const u8 {
    deref!(vec).as_ptr()
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_vector_get_size(vec: *const Vec<u8>) -> usize {
    deref!(vec).len()
}

/// Note: Returned string is not null terminated
/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_string_get_ptr(s: *const String) -> *const u8 {
    deref!(s).as_ptr()
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_string_get_size(s: *const String) -> usize {
    deref!(s).len()
}
