/*
 * Copyright 2023 G-Core Innovations SARL
 */

use std::net::IpAddr;

use crate::bindings::ngx_connection_t;

pub struct Connection(ngx_connection_t);

impl Connection {
    pub(crate) unsafe fn from_raw<'a>(ptr: *const ngx_connection_t) -> Option<&'a Self> {
        ptr.cast::<Self>().as_ref()
    }

    pub fn client_ip(&self) -> Option<IpAddr> {
        unsafe {
            if (*self.0.sockaddr).sa_family == libc::AF_INET as u16 {
                let sockaddr_in: *const libc::sockaddr_in = self.0.sockaddr.cast();
                Some((*sockaddr_in).sin_addr.s_addr.to_ne_bytes().into())
            } else if (*self.0.sockaddr).sa_family == libc::AF_INET6 as u16 {
                let sockaddr_in: *const libc::sockaddr_in6 = self.0.sockaddr.cast();
                Some((*sockaddr_in).sin6_addr.s6_addr.into())
            } else {
                None
            }
        }
    }
}
