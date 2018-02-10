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
