#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum nss_status {
    TryAgain = -2,
    Unavail = -1,
    NotFound = 0,
    Success = 1,
}

#[repr(C)]
pub struct gaih_addrtuple {
    pub next: *mut gaih_addrtuple,
    pub name: *mut u8,
    pub family: i32,
    pub addr: [u32; 4],
    pub scopeid: u32,
}

#[repr(C)]
pub struct hostent {
    pub h_name: *mut u8,
    pub h_aliases: *mut *mut u8,
    pub h_addrtype: i32,
    pub h_length: i32,
    pub h_addr_list: *mut *mut u8,
}
