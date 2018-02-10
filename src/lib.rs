extern crate dnsoverhttps;
#[cfg(feature = "log")]
#[macro_use]
extern crate log;

use std::os::raw::c_char;
use std::ffi::CStr;
use std::ptr;

use dnsoverhttps::resolve_host;

#[cfg(not(feature = "log"))]
#[macro_use]
mod log;

mod write;
mod consts;
mod structs;
use write::{write_addresses4, write_addresses3};
use consts::{errno, netdb, af};
pub use structs::{nss_status, gaih_addrtuple, hostent};

#[no_mangle]
pub extern "C" fn _nss_dnsoverhttps_gethostbyname4_r(
    orig_name: *const c_char,
    pat: *mut *mut gaih_addrtuple,
    buffer: *mut u8,
    buflen: usize,
    errnop: *mut i32,
    h_errnop: *mut i32,
    ttlp: *mut i32) -> nss_status {

    debug!("Resolving with gethostbyname4_r");

    unsafe {
        let slice = CStr::from_ptr(orig_name);
        let name = slice.to_string_lossy();
        debug!("Resolving host '{}'", name);
        let addrs = match resolve_host(&name) {
            Ok(a) => a,
            Err(_) => {
                *errnop = errno::EINVAL;
                *h_errnop = netdb::NO_RECOVERY;
                return nss_status::Unavail;
            }
        };
        debug!("Found {} addresses", addrs.len());
        debug!("Addresses: {:?}", addrs);

        write_addresses4(orig_name, pat, buffer, buflen, errnop, h_errnop, ttlp,
            &addrs)
    }
}

#[no_mangle]
pub extern "C" fn _nss_dnsoverhttps_gethostbyname3_r(
    orig_name: *const c_char,
    af: i32,
    result: *mut hostent,
    buffer: *mut u8, buflen: usize,
    errnop: *mut i32, h_errnop: *mut i32,
    ttlp: *mut i32, canonp: *mut *mut u8) -> nss_status {

    debug!("Resolving with gethostbyname3_r");

    unsafe {
        let slice = CStr::from_ptr(orig_name);
        let name = slice.to_string_lossy();
        debug!("Resolving host '{}'", name);
        let addrs = match resolve_host(&name) {
            Ok(a) => a,
            Err(_) => {
                *errnop = errno::EINVAL;
                *h_errnop = netdb::NO_RECOVERY;
                return nss_status::Unavail;
            }
        };
        let addrs : Vec<_> = addrs.into_iter()
            .filter(|addr| {
                if af == af::INET {
                    addr.is_ipv4()
                } else if af == af::INET6 {
                    addr.is_ipv6()
                } else {
                    true
                }
            })
            .collect();
        debug!("Found {} addresses", addrs.len());
        debug!("Addresses: {:?}", addrs);

        write_addresses3(orig_name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp,
                         &addrs)
    }
}

// Forwarding implementations

#[no_mangle]
pub extern "C" fn _nss_dnsoverhttps_gethostbyname2_r(
    name: *const c_char,
    af: i32,
    host: *mut hostent,
    buffer: *mut u8, buflen: usize,
    errnop: *mut i32, h_errnop: *mut i32) -> nss_status {
    return _nss_dnsoverhttps_gethostbyname3_r(
        name,
        af,
        host,
        buffer, buflen,
        errnop, h_errnop,
        ptr::null_mut(),
        ptr::null_mut());
}

#[no_mangle]
pub extern "C" fn _nss_dnsoverhttps_gethostbyname_r(
    name: *const c_char,
    host: *mut hostent,
    buffer: *mut u8, buflen: usize,
    errnop: *mut i32, h_errnop: *mut i32) -> nss_status {
    let mut ret = _nss_dnsoverhttps_gethostbyname3_r(
        name,
        af::INET6,
        host,
        buffer, buflen,
        errnop, h_errnop,
        ptr::null_mut(),
        ptr::null_mut());

	if ret == nss_status::NotFound {
        ret = _nss_dnsoverhttps_gethostbyname3_r(
            name,
            af::INET,
            host,
            buffer, buflen,
            errnop, h_errnop,
            ptr::null_mut(),
            ptr::null_mut());
    }

	return ret;
}
