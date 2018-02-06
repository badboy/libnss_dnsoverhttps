extern crate dnsoverhttps;

use std::os::raw::c_char;
use std::ffi::CStr;
use std::net::IpAddr;

use dnsoverhttps::resolve_host;

type NssStatus = i32;

const AF_INET : i32 = 2;
const AF_INET6 : i32 = 10;
const NSS_STATUS_UNAVAIL : i32 = -1;
const EINVAL : i32 = 22;
const NO_RECOVERY : i32 = 3;

#[repr(C)]
#[derive(Debug)]
pub struct AddrTuple {
    family: i32,
    addr: [u8; 16]
}

fn ip_addr_to_tuple(addr: IpAddr) -> AddrTuple {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let mut data = [0; 16];
            data[0..4].copy_from_slice(&octets);
            AddrTuple {
                family: AF_INET,
                addr: data,
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut data = [0; 16];
            data.copy_from_slice(&octets);
            AddrTuple {
                family: AF_INET,
                addr: data,
            }
        }
    }
}

extern {
    fn write_addresses3(name: *const c_char,
                        af: i32,
                        result: *mut u8,
                        buffer: *mut c_char, buflen: usize,
                        errnop: *mut i32, h_errnop: *mut i32,
                        ttlp: *mut i32, canonp: *mut *mut c_char,
                        addr: *const AddrTuple, addr_len: usize) -> NssStatus;

    fn write_addresses4(name: *const c_char,
                       pat: *mut *mut u8,
                       buffer: *mut u8, buflen: usize,
                       errnop: *mut i32,
                       h_errnop: *mut i32,
                       ttlp: *mut i32,
                       addr: *const AddrTuple, addr_len: usize) -> NssStatus;
}

#[no_mangle]
pub extern "C" fn _nss_dnsoverhttps_gethostbyname4_r(
    orig_name: *const c_char,
    pat: *mut *mut u8,
    buffer: *mut u8,
    buflen: usize,
    errnop: *mut i32,
    h_errnop: *mut i32,
    ttlp: *mut i32) -> NssStatus {

    unsafe {
        let slice = CStr::from_ptr(orig_name);
        let name = slice.to_string_lossy();
        let addrs = match resolve_host(&name) {
            Ok(a) => a,
            Err(_) => {
                *errnop = EINVAL;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
            }
        };
        let addrs : Vec<_> = addrs.into_iter().map(ip_addr_to_tuple).collect();

        write_addresses4(orig_name, pat, buffer, buflen, errnop, h_errnop, ttlp,
            addrs.as_ptr(), addrs.len())
    }
}

#[no_mangle]
pub extern "C" fn _nss_dnsoverhttps_gethostbyname3_r(
    orig_name: *const c_char,
    af: i32,
    result: *mut u8,
    buffer: *mut c_char, buflen: usize,
    errnop: *mut i32, h_errnop: *mut i32,
    ttlp: *mut i32, canonp: *mut *mut c_char) -> NssStatus {

    unsafe {
        let slice = CStr::from_ptr(orig_name);
        let name = slice.to_string_lossy();
        let addrs = match resolve_host(&name) {
            Ok(a) => a,
            Err(_) => {
                *errnop = EINVAL;
                *h_errnop = NO_RECOVERY;
                return NSS_STATUS_UNAVAIL;
            }
        };
        let addrs : Vec<_> = addrs.into_iter()
            .filter(|addr| {
                if af == AF_INET {
                    addr.is_ipv4()
                } else if af == AF_INET6 {
                    addr.is_ipv6()
                } else {
                    true
                }
            })
            .map(ip_addr_to_tuple)
            .collect();

        write_addresses3(orig_name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp,
                         addrs.as_ptr(), addrs.len())
    }
}
