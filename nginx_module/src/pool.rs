/*
 * Copyright 2024 G-Core Innovations SARL
 */

use std::{ffi::c_void, ptr::addr_of};

use crate::bindings::{ngx_palloc, ngx_pool_cleanup_add, ngx_pool_t};

pub struct Pool(ngx_pool_t);

impl Pool {
    ///
    /// # Safety
    ///  
    /// `ptr` should be a valid ngx_pool_t pointer
    ///  Also unsafe as it can assign an arbitrary lifetime.
    ///
    pub unsafe fn from_raw<'a>(ptr: *mut ngx_pool_t) -> &'a mut Self {
        &mut *(ptr as *mut Self)
    }

    pub fn alloc<T: Default>(&mut self) -> anyhow::Result<&mut T> {
        unsafe {
            let cleaner = ngx_pool_cleanup_add(&mut self.0, std::mem::size_of::<T>());
            anyhow::ensure!(
                !cleaner.is_null(),
                "ngx_pool: ngx_pool_cleanup_add returned NULL"
            );

            let ptr: *mut T = (*cleaner).data.cast();

            anyhow::ensure!(
                !ptr.is_null(),
                "ngx_pool: Could not allocate {} bytes of memory",
                std::mem::size_of::<T>()
            );

            std::ptr::write(ptr, T::default());

            unsafe extern "C" fn cleanup<T>(data: *mut c_void) {
                std::ptr::drop_in_place(data as *mut T);
            }

            (*cleaner).handler = Some(cleanup::<T>);

            Ok(&mut *ptr)
        }
    }

    pub fn alloc_bytes(&self, size: usize) -> anyhow::Result<&mut [u8]> {
        unsafe {
            let ptr = ngx_palloc(addr_of!(self.0).cast_mut(), size);
            anyhow::ensure!(
                !ptr.is_null(),
                "ngx_pool: Could not allocate {} bytes of memory",
                size
            );
            Ok(std::slice::from_raw_parts_mut(ptr.cast(), size))
        }
    }

    pub(crate) fn inner(&mut self) -> *mut ngx_pool_t {
        &mut self.0
    }
}
