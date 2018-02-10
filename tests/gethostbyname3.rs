extern crate nss_dnsoverhttps;
#[cfg(feature = "log")]
extern crate log;
extern crate env_logger;

use std::str::FromStr;
use std::ptr;
use std::ffi::CString;
use std::net::{Ipv6Addr, Ipv4Addr};
use std::sync::{Once, ONCE_INIT};

use nss_dnsoverhttps::*;

static START: Once = ONCE_INIT;

#[test]
fn resolves_v6() {
    START.call_once(|| {
        env_logger::init();
    });

    unsafe {
        let name = CString::new("example.com").unwrap();
        let buflen = 1024;
        let mut buf : Vec<u8> = Vec::with_capacity(buflen);
        let result_buf : Box<hostent> = Box::new(std::mem::uninitialized());
        let result_buf = Box::into_raw(result_buf);

        let mut errnop = 42;
        let mut h_errnop = 42;

        assert_eq!(nss_status::Success, _nss_dnsoverhttps_gethostbyname3_r(
                name.as_ptr(),
                /* AF_INET6 */ 10,
                result_buf,
                buf.as_mut_ptr(),
                buflen,
                &mut errnop,
                &mut h_errnop,
                ptr::null_mut(),
                ptr::null_mut()));

        assert_eq!(0, errnop);
        assert_eq!(0, h_errnop);

        let result_buf = Box::from_raw(result_buf);

        assert_eq!(10, result_buf.h_addrtype);

        let mut ip = [0; 16];
        let src = *result_buf.h_addr_list;
        ptr::copy(src, ip.as_mut_ptr(), 16);
        let ip = Ipv6Addr::from(ip);

        let exp = Ipv6Addr::from_str("2606:2800:220:1:248:1893:25c8:1946").unwrap();
        assert_eq!(exp, ip);
    }
}

#[test]
fn resolves_v4() {
    START.call_once(|| {
        env_logger::init();
    });

    unsafe {
        let name = CString::new("example.com").unwrap();
        let buflen = 1024;
        let mut buf : Vec<u8> = Vec::with_capacity(buflen);
        let result_buf : Box<hostent> = Box::new(std::mem::uninitialized());
        let result_buf = Box::into_raw(result_buf);

        let mut errnop = 42;
        let mut h_errnop = 42;

        assert_eq!(nss_status::Success, _nss_dnsoverhttps_gethostbyname3_r(
                name.as_ptr(),
                /* AF_INET */ 2,
                result_buf,
                buf.as_mut_ptr(),
                buflen,
                &mut errnop,
                &mut h_errnop,
                ptr::null_mut(),
                ptr::null_mut()));

        assert_eq!(0, errnop);
        assert_eq!(0, h_errnop);

        let result_buf = Box::from_raw(result_buf);

        assert_eq!(2, result_buf.h_addrtype);

        let mut ip = [0; 4];
        let src = *result_buf.h_addr_list;
        ptr::copy(src, ip.as_mut_ptr(), 4);
        let ip = Ipv4Addr::from(ip);

        let exp = Ipv4Addr::from_str("93.184.216.34").unwrap();
        assert_eq!(exp, ip);
    }
}

#[test]
fn resolves_nonexistent() {
    START.call_once(|| {
        env_logger::init();
    });

    unsafe {
        let name = CString::new("foobarfoo").unwrap();
        let buflen = 1024;
        let mut buf : Vec<u8> = Vec::with_capacity(buflen);
        let result_buf : Box<hostent> = Box::new(std::mem::uninitialized());
        let result_buf = Box::into_raw(result_buf);

        let mut errnop = 42;
        let mut h_errnop = 42;

        assert_eq!(nss_status::NotFound, _nss_dnsoverhttps_gethostbyname3_r(
                name.as_ptr(),
                /* AF_INET6 */ 10,
                result_buf,
                buf.as_mut_ptr(),
                buflen,
                &mut errnop,
                &mut h_errnop,
                ptr::null_mut(),
                ptr::null_mut()));

        assert_eq!(3, errnop);
        assert_eq!(3, h_errnop);

        let _result_buf = Box::from_raw(result_buf);
    }
}

#[test]
fn resolves_smallbuffer() {
    START.call_once(|| {
        env_logger::init();
    });

    unsafe {
        let name = CString::new("google.com").unwrap();
        let buflen = 32;
        let mut buf : Vec<u8> = Vec::with_capacity(buflen);
        let result_buf : Box<hostent> = Box::new(std::mem::uninitialized());
        let result_buf = Box::into_raw(result_buf);

        let mut errnop = 42;
        let mut h_errnop = 42;

        assert_eq!(nss_status::TryAgain, _nss_dnsoverhttps_gethostbyname3_r(
                name.as_ptr(),
                /* AF_INET6 */ 10,
                result_buf,
                buf.as_mut_ptr(),
                buflen,
                &mut errnop,
                &mut h_errnop,
                ptr::null_mut(),
                ptr::null_mut()));

        assert_eq!(34, errnop);
        assert_eq!(-1, h_errnop);

        let _result_buf = Box::from_raw(result_buf);
    }
}
