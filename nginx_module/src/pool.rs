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

    pub fn alloc<T: Default>(&self) -> anyhow::Result<&mut T> {
        unsafe {
            let cleaner = ngx_pool_cleanup_add(
                &self.0 as *const ngx_pool_t as *mut ngx_pool_t,
                std::mem::size_of::<T>(),
            );
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

    pub fn add_cleanup_handler<F: FnOnce()>(&self, f: F) -> anyhow::Result<()> {
        struct Helper<T: FnOnce()>(Option<T>);
        impl<T: FnOnce()> Default for Helper<T> {
            fn default() -> Self {
                Self(None)
            }
        }
        impl<T: FnOnce()> Drop for Helper<T> {
            fn drop(&mut self) {
                if let Some(f) = self.0.take() {
                    f();
                }
            }
        }

        let a = self.alloc::<Helper<F>>()?;
        a.0 = Some(f);
        Ok(())
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

    pub fn raw(&self) -> *mut ngx_pool_t {
        (&self.0 as *const ngx_pool_t).cast_mut()
    }
}
