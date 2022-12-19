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

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_ipv4addr_get_data(ip: *const std::net::Ipv4Addr) -> u32 {
    u32::from_be_bytes(deref!(ip).octets())
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_ipv6addr_get_data(ip: *const std::net::Ipv6Addr) -> *const u8 {
    deref!(ip).octets().as_slice().as_ptr()
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_ipaddr_is_v4(ip: *const std::net::IpAddr) -> bool {
    deref!(ip).is_ipv4()
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_ipaddr_is_v6(ip: *const std::net::IpAddr) -> bool {
    deref!(ip).is_ipv6()
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_ipaddr_as_v4(
    ip: *const std::net::IpAddr,
) -> *const std::net::Ipv4Addr {
    if let std::net::IpAddr::V4(addr) = deref!(ip) {
        addr
    } else {
        std::ptr::null()
    }
}

/// # Safety
/// function will panic if called with null
#[no_mangle]
pub unsafe extern "C" fn sawp_ipaddr_as_v6(
    ip: *const std::net::IpAddr,
) -> *const std::net::Ipv6Addr {
    if let std::net::IpAddr::V6(addr) = deref!(ip) {
        addr
    } else {
        std::ptr::null()
    }
}
