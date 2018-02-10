use std::os::raw::c_char;
use std::ffi::CStr;
use std::{mem, ptr};
use std::net::IpAddr;
use consts::{errno, netdb, af};
use structs::{nss_status, gaih_addrtuple};

fn align(l: usize) -> usize {
    (l+7) & !1
}

pub unsafe fn write_addresses4(
    name: *const c_char,
    pat: *mut *mut gaih_addrtuple,
    buffer: *mut u8, buflen: usize,
    errnop: *mut i32, h_errnop: *mut i32,
    ttlp: *mut i32,
    addrs: &[IpAddr]) -> nss_status {

    if addrs.len() == 0 {
        *errnop = errno::ESRCH;
        *h_errnop = netdb::HOST_NOT_FOUND;
        return nss_status::NotFound;
    }

    let r_name = buffer;
    let s_name = CStr::from_ptr(name);
    let l = s_name.to_bytes().len();
    let ms = align(l+1) + align(mem::size_of::<gaih_addrtuple>()) * addrs.len();
    if buflen < ms {
        *errnop = errno::ERANGE;
        *h_errnop = netdb::NETDB_INTERNAL;
        return nss_status::TryAgain;
    }

    ptr::copy(name as *const u8, r_name, l+1);
    let mut idx = align(l+1) as isize;

    let mut r_tuple;
    let r_tuple_first = buffer.offset(idx);

    for (i, addr) in addrs.iter().enumerate() {
        r_tuple = buffer.offset(idx);
        let mut o_tuple = mem::transmute::<_, &mut gaih_addrtuple>(r_tuple);

        if i == addrs.len()-1 {
            o_tuple.next = ptr::null_mut();
        } else {
            let next = r_tuple.offset(align(mem::size_of::<gaih_addrtuple>()) as isize);
            o_tuple.next = mem::transmute::<_, *mut gaih_addrtuple>(next);
        }

        o_tuple.name = r_name;
        o_tuple.scopeid = 0;
        match *addr {
            IpAddr::V4(ip) => {
                o_tuple.family = af::INET;
                let data = ip.octets();
                let dst = o_tuple.addr.as_mut_ptr() as *mut u8;
                ptr::copy(data.as_ptr(), dst, 4);
            }
            IpAddr::V6(ip) => {
                o_tuple.family = af::INET6;
                let data = ip.octets();
                let mut dst = o_tuple.addr.as_mut_ptr() as *mut u8;
                ptr::copy(data.as_ptr(), dst, 16);

            }
        }

        idx += align(mem::size_of::<gaih_addrtuple>()) as isize;
    }

    if (*pat).is_null() {
        *pat = mem::transmute::<_, *mut gaih_addrtuple>(r_tuple_first);
    } else {
        **pat = ptr::read(r_tuple_first as *mut gaih_addrtuple);
    }

    if !ttlp.is_null() {
        *ttlp = 0;
    }

    *errnop = 0;
    *h_errnop = netdb::NETDB_SUCCESS;

    nss_status::Success
}
