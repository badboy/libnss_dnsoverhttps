pub mod errno {
    pub const EINVAL : i32 = 22;
    pub const ESRCH : i32 = 3;
    pub const ERANGE : i32 = 34;
}

pub mod netdb {
    pub const NETDB_INTERNAL : i32 = -1;
    pub const NETDB_SUCCESS : i32 = 0;
    pub const HOST_NOT_FOUND : i32 = 3;
    pub const NO_RECOVERY : i32 = 3;
}

pub mod af {
    pub const INET : i32 = 2;
    pub const INET6 : i32 = 10;
}
