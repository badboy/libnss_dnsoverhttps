use std::os::raw::c_char;
use std::ffi::CStr;
use std::{mem, ptr, slice};
use std::net::IpAddr;
use consts::{errno, netdb, af};
use structs::{nss_status, gaih_addrtuple, hostent};

fn align(l: usize) -> usize {
    (l+7) & !1
}

#[inline]
fn family_address_size(family: i32) -> usize {
    if family == af::INET6 {
        16
    } else {
        4
    }
}

pub unsafe fn write_addresses4(
    name: *const c_char,
    pat: *mut *mut gaih_addrtuple,
    buffer: *mut u8, buflen: usize,
    errnop: *mut i32, h_errnop: *mut i32,
    ttlp: *mut i32,
    addrs: &[IpAddr]) -> nss_status {

    debug!("Writing {} addresses", addrs.len());

    if addrs.len() == 0 {
        *errnop = errno::ESRCH;
        *h_errnop = netdb::HOST_NOT_FOUND;
        return nss_status::NotFound;
    }

    let r_name = buffer;
    let s_name = CStr::from_ptr(name);
    let l = s_name.to_bytes().len();
    let ms = align(l+1) + align(mem::size_of::<gaih_addrtuple>()) * addrs.len();
    debug!("Expected size: {}, buffer size: {}", ms, buflen);
    if buflen < ms {
        *errnop = errno::ERANGE;
        *h_errnop = netdb::NETDB_INTERNAL;
        return nss_status::TryAgain;
    }

    debug!("Copying the name into {:p} ({} bytes)", r_name, l+1);
    ptr::copy(name as *const u8, r_name, l+1);
    let mut idx = align(l+1) as isize;
    debug!("Copied. Next starting at index {} (p: {:p})", idx, buffer.offset(idx));

    let mut r_tuple;
    let r_tuple_first = buffer.offset(idx);

    for (i, addr) in addrs.iter().enumerate() {
        debug!("Looking at address {}: {:?}", i, addr);
        r_tuple = buffer.offset(idx);
        let mut o_tuple = mem::transmute::<_, &mut gaih_addrtuple>(r_tuple);

        if i == addrs.len()-1 {
            debug!("At the end, no next element");
            o_tuple.next = ptr::null_mut();
        } else {
            let next = r_tuple.offset(align(mem::size_of::<gaih_addrtuple>()) as isize);
            debug!("Current element: {:p}, next element: {:p})", r_tuple, next);
            o_tuple.next = mem::transmute::<_, *mut gaih_addrtuple>(next);
        }

        o_tuple.name = r_name;
        o_tuple.scopeid = 0;
        match *addr {
            IpAddr::V4(ip) => {
                debug!("Found v4, copying 4 bytes");
                o_tuple.family = af::INET;
                let data = ip.octets();
                let dst = o_tuple.addr.as_mut_ptr() as *mut u8;
                debug!("Src: {:p}, Dst: {:p}", data.as_ptr(), dst);
                ptr::copy(data.as_ptr(), dst, 4);
            }
            IpAddr::V6(ip) => {
                debug!("Found v4, copying 16 bytes");
                o_tuple.family = af::INET6;
                let data = ip.octets();
                let mut dst = o_tuple.addr.as_mut_ptr() as *mut u8;
                debug!("Src: {:p}, Dst: {:p}", data.as_ptr(), dst);
                ptr::copy(data.as_ptr(), dst, 16);

            }
        }

        idx += align(mem::size_of::<gaih_addrtuple>()) as isize;
        debug!("Next idx: {}", idx);
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

pub unsafe fn write_addresses3(
    name: *const c_char,
    af: i32,
    result: *mut hostent,
    buffer: *mut u8, buflen: usize,
    errnop: *mut i32, h_errnop: *mut i32,
    ttlp: *mut i32,
    canonp: *mut *mut u8,
    addrs: &[IpAddr]) -> nss_status {

    debug!("Writing {} addresses (write_addresses3)", addrs.len());

    if addrs.len() == 0 {
        *errnop = errno::ESRCH;
        *h_errnop = netdb::HOST_NOT_FOUND;
        return nss_status::NotFound;
    }

    let alen = family_address_size(af);
    let s_name = CStr::from_ptr(name);
    let l = s_name.to_bytes().len();
    let ms = align(l+1) + addrs.len() * align(alen) + (addrs.len()+2) * mem::size_of::<u8>();

    debug!("Expected size: {}, buffer size: {}", ms, buflen);
    if buflen < ms {
        *errnop = errno::ERANGE;
        *h_errnop = netdb::NETDB_INTERNAL;
        return nss_status::TryAgain;
    }

    let r_name = buffer;
    debug!("Copying the name into {:p} ({} bytes)", r_name, l+1);
    ptr::copy(name as *const u8, r_name, l+1);
    let mut idx = align(l+1) as isize;
    debug!("Copied. Next starting at index {} (p: {:p})", idx, buffer.offset(idx));

    let r_aliases = buffer.offset(idx);
    *r_aliases = 0;
    idx += mem::size_of::<usize>() as isize;

    let r_addr = buffer.offset(idx);

    for (i, addr) in addrs.iter().enumerate() {
        let dst = r_addr.offset((i*align(alen)) as isize);
        match *addr {
            IpAddr::V4(ip) => {
                let data = ip.octets();
                ptr::copy(data.as_ptr(), dst, alen);
            }
            IpAddr::V6(ip) => {
                let data = ip.octets();
                ptr::copy(data.as_ptr(), dst, alen);
            }
        }
    }
    idx += (addrs.len() * align(alen)) as isize;

    let r_addr_list = buffer.offset(idx);
    let s_addr_list : &mut [*mut u8] = slice::from_raw_parts_mut(r_addr_list as *mut *mut u8, addrs.len());
    for (i, _) in addrs.iter().enumerate() {
        s_addr_list[i] = r_addr.offset((i * align(alen)) as isize);
    }

    let o_result = &mut *result;
    o_result.h_name = r_name;
    o_result.h_aliases = r_aliases as *mut *mut _;
    o_result.h_addrtype = af;
    o_result.h_length = alen as i32;
    o_result.h_addr_list = r_addr_list as *mut *mut _;


    if !ttlp.is_null() {
        *ttlp = 0;
    }

    if !canonp.is_null() {
        *canonp = r_name;
    }

    *errnop = 0;
    *h_errnop = netdb::NETDB_SUCCESS;

    nss_status::Success
}
