/*
 * Copyright 2023 G-Core Innovations SARL
 */

use std::{marker::PhantomData, ptr::NonNull};

use bitflags::bitflags;

use crate::{
    bindings::{self, ngx_conf_t, ngx_hex_dump, ngx_http_variable_t},
    Log, NgxStr, Pool,
};

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HttpVarFlags: u32 {
        const CHANGEABLE = bindings::NGX_HTTP_VAR_CHANGEABLE;
        const NOCACHEABLE = bindings::NGX_HTTP_VAR_NOCACHEABLE;
        const NOHASH = bindings::NGX_HTTP_VAR_NOHASH;
    }
}

#[repr(transparent)]
pub struct NgxConfig<'pool> {
    inner: ngx_conf_t,
    phantom: PhantomData<&'pool ()>,
}

impl<'pool> NgxConfig<'pool> {
    ///
    /// # Safety
    ///  
    ///  `ptr` should be a valid ngx_conf_t pointer.
    ///  Also use it care as it can assign an arbitrary lifetime.
    ///
    pub unsafe fn new<'a>(ptr: *mut ngx_conf_t) -> &'a mut NgxConfig<'pool> {
        &mut *(ptr as *mut NgxConfig)
    }

    pub fn add_variable(
        &mut self,
        name: &[u8],
        flags: HttpVarFlags,
    ) -> Option<&mut ngx_http_variable_t> {
        let name = NgxStr::from(name);
        let var_ptr = unsafe {
            bindings::ngx_http_add_variable(
                &mut self.inner,
                name.as_mut_ptr_unsafe(),
                flags.bits() as usize,
            )
        };
        unsafe { NonNull::new(var_ptr).map(|mut p| p.as_mut()) }
    }

    pub(crate) fn ptr_mut(&mut self) -> *mut ngx_conf_t {
        &mut self.inner
    }

    pub(crate) unsafe fn ptr_mut_unsafe(&self) -> *mut ngx_conf_t {
        (&self.inner as *const ngx_conf_t).cast_mut()
    }

    pub fn pool(&mut self) -> &mut Pool {
        unsafe { Pool::from_raw(self.inner.pool) }
    }

    pub fn log(&self) -> &Log {
        unsafe { Log::new(self.inner.log) }
    }
}

pub fn hex_dump(dest: &mut [u8], src: &[u8]) {
    assert_eq!(dest.len(), src.len() * 2);
    unsafe {
        ngx_hex_dump(dest.as_mut_ptr(), src.as_ptr().cast_mut(), src.len());
    }
}

#[cfg(not(nginx_version_1023000))]
pub unsafe fn array_init(
    array: *mut crate::bindings::ngx_array_t,
    pool: *mut crate::bindings::ngx_pool_t,
    n: usize,
    size: usize,
) -> isize {
    let array = &mut *array;
    array.nelts = 0;
    array.size = size;
    array.nalloc = n;
    array.pool = pool;
    array.elts = crate::bindings::ngx_palloc(pool, n * size);
    if array.elts.is_null() {
        crate::bindings::NGX_ERROR as isize
    } else {
        crate::bindings::NGX_OK as isize
    }
}

#[cfg(test)]
mod tests {
    use crate::{bindings::ngx_conf_t, wrappers::NgxConfig};

    #[test]
    fn check_config_size() {
        assert_eq!(
            std::mem::size_of::<ngx_conf_t>(),
            std::mem::size_of::<NgxConfig<'static>>()
        );
    }
}
