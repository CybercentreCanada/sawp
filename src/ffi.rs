use sawp_ffi::deref;

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
