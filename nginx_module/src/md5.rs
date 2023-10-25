/*
 * Copyright 2023 G-Core Innovations SARL
 */

use std::mem::MaybeUninit;

use crate::bindings::{ngx_md5_final, ngx_md5_init, ngx_md5_t, ngx_md5_update};

pub struct Md5(ngx_md5_t);

pub const MD5_DIGEST_LENGTH: usize = 16;

impl Md5 {
    pub fn init() -> Self {
        let mut inner = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe { ngx_md5_init(&mut inner) };
        Self(inner)
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe { ngx_md5_update(&mut self.0, data.as_ptr().cast(), data.len()) }
    }

    pub fn finish(mut self) -> [u8; MD5_DIGEST_LENGTH] {
        let mut result = [0; MD5_DIGEST_LENGTH];
        unsafe {
            ngx_md5_final(result.as_mut_ptr(), &mut self.0);
        }
        result
    }
}
