/*
 * Copyright 2023 G-Core Innovations SARL
 */

use std::{
    marker::PhantomData,
    ptr::{addr_of, addr_of_mut},
};

use crate::bindings::ngx_str_t;

use super::Pool;

/// NgxStr is an abstraction over ngx_str_t. It has the same memory layout as the underlying `inner` ngx_str_t (the `lifetime` field is zero sized).
/// In addition to ngx_str_t NgxStr also tracks the lifetime of the underlying byte chunk, most times this is the lifetime of the pool it was allocated from.
#[derive(Copy, Clone)]
pub struct NgxStr<'a> {
    inner: ngx_str_t,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> Default for NgxStr<'a> {
    fn default() -> Self {
        Self::null()
    }
}

impl<'a> From<&'a [u8]> for NgxStr<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::new(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for NgxStr<'a> {
    fn from(value: &'a [u8; N]) -> Self {
        Self::new_from_array(value)
    }
}

impl<'a, 'b> PartialEq<NgxStr<'b>> for NgxStr<'a> {
    fn eq(&self, other: &NgxStr<'b>) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

/// Utility enum used in NgxStr::build
pub enum Builder<'a> {
    Counter(usize),
    Builder(&'a mut [u8]),
    Error,
}

impl<'a> NgxStr<'a> {
    ///
    /// # Safety
    ///  
    ///  unsafe as it can assign an arbitrary lifetime
    ///
    pub unsafe fn from_raw(inner: ngx_str_t) -> Self {
        Self {
            inner,
            lifetime: PhantomData,
        }
    }

    pub fn as_bytes(self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(self.inner.data, self.inner.len) }
    }

    ///
    /// # Safety
    ///  
    /// Should only be used on valid UTF-8 strings
    ///
    pub unsafe fn as_str_unchecked(self) -> &'a str {
        std::str::from_utf8_unchecked(self.as_bytes())
    }

    //TODO: remove once const trait implementation gets stabilized
    pub const fn new(value: &'a [u8]) -> Self {
        Self {
            inner: ngx_str_t {
                len: value.len(),
                data: value.as_ptr().cast_mut(),
            },
            lifetime: PhantomData,
        }
    }

    pub const fn new_from_array<const N: usize>(value: &'a [u8; N]) -> Self {
        Self {
            inner: ngx_str_t {
                len: N,
                data: value.as_ptr().cast_mut(),
            },
            lifetime: PhantomData,
        }
    }

    pub const fn new_from_nil_terminated<const N: usize>(value: &'a [u8; N]) -> Self {
        Self {
            inner: ngx_str_t {
                len: N - 1,
                data: value.as_ptr().cast_mut(),
            },
            lifetime: PhantomData,
        }
    }

    pub const fn null() -> Self {
        Self {
            inner: ngx_str_t {
                len: 0,
                data: std::ptr::null_mut(),
            },
            lifetime: PhantomData,
        }
    }

    /// This method encapsulates the pattern where a string is allocated from a pool, but the string parts are iterated one time to
    /// compute the allocated length and only then the string is allocated and copied into.
    /// The build_fn closure allows adding to the result string and it is called twice - once to compute the length and second to actually copy
    /// The build_fn closure should behave the same both times - if the computed length does not match what is copied the second time this will return Err.
    pub fn build(pool: &'a Pool, build_fn: impl Fn(&mut Builder)) -> anyhow::Result<Self> {
        let mut builder = Builder::Counter(0);
        build_fn(&mut builder);
        match builder {
            Builder::Counter(n) => {
                let data = pool.alloc_bytes(n)?;
                let mut builder = Builder::Builder(data);
                build_fn(&mut builder);
                if let Builder::Builder(s) = builder {
                    if s.is_empty() {
                        Ok(NgxStr::new(data))
                    } else {
                        Err(anyhow::anyhow!(
                            "Inconsistent builder, cannot create string"
                        ))
                    }
                } else {
                    Err(anyhow::anyhow!(
                        "Inconsistent builder, cannot create string"
                    ))
                }
            }
            Builder::Builder(s) => Ok(NgxStr::new(s)),
            Builder::Error => Err(anyhow::anyhow!(
                "Inconsistent builder, cannot create string"
            )),
        }
    }

    pub(crate) unsafe fn as_mut_ptr_unsafe(&self) -> *mut ngx_str_t {
        addr_of!(self.inner).cast_mut()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut ngx_str_t {
        addr_of_mut!(self.inner)
    }

    pub const fn inner(self) -> ngx_str_t {
        self.inner
    }

    pub const fn is_empty(self) -> bool {
        self.inner.len == 0
    }
}

impl<'a> Builder<'a> {
    pub fn append<'b>(&'b mut self, value: &'b [u8]) {
        match self {
            &mut Builder::Counter(ref mut n) => *n += value.len(),
            &mut Builder::Builder(ref mut data) => {
                if data.len() < value.len() {
                    *self = Builder::Error;
                } else {
                    let d = std::mem::take(data);
                    let (start, end): (&'a mut [u8], &'a mut [u8]) = d.split_at_mut(value.len());
                    start.copy_from_slice(value);
                    *data = end;
                }
            }
            Builder::Error => (), // Do nothing if error already encountered
        }
    }
}
