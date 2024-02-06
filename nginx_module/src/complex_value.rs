/*
 * Copyright 2024 G-Core Innovations SARL
 */

use std::{marker::PhantomData, mem::MaybeUninit};

use super::{HttpRequest, NgxConfig, NgxStr};
use crate::{
    bindings::{
        ngx_http_compile_complex_value,
        ngx_http_compile_complex_value_t,
        ngx_http_complex_value,
        ngx_http_complex_value_t,
        ngx_palloc,
        NGX_OK,
    },
    ConfigValue,
};

#[derive(Copy, Clone)]
pub struct ComplexValue<'a> {
    inner: *mut ngx_http_complex_value_t,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> Default for ComplexValue<'a> {
    fn default() -> Self {
        Self {
            inner: std::ptr::null_mut(),
            _phantom: PhantomData,
        }
    }
}

impl<'a> ConfigValue<'a> for ComplexValue<'a> {
    fn config_directive(
        &mut self,
        conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        let value = values[0];
        if value.is_empty() {
            self.inner = std::ptr::null_mut();
        } else {
            unsafe {
                let mut compiler: ngx_http_compile_complex_value_t =
                    MaybeUninit::zeroed().assume_init();
                compiler.cf = conf.ptr_mut();
                compiler.value = value.as_mut_ptr_unsafe();

                let complex_value: *mut ngx_http_complex_value_t = ngx_palloc(
                    conf.pool().inner(),
                    std::mem::size_of::<ngx_http_complex_value_t>(),
                )
                .cast();
                compiler.complex_value = complex_value;

                anyhow::ensure!(
                    ngx_http_compile_complex_value(&mut compiler) == NGX_OK as isize,
                    "Complex value compilation error"
                );

                self.inner = complex_value;
            }
        }

        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        if self.is_empty() {
            self.inner = other.inner;
        }
    }
}

impl ComplexValue<'_> {
    pub fn is_empty(&self) -> bool {
        self.inner.is_null()
    }

    pub fn eval(&self, req: &HttpRequest) -> anyhow::Result<NgxStr> {
        let mut result = NgxStr::default();
        if !self.inner.is_null() {
            anyhow::ensure!(
                unsafe { ngx_http_complex_value(req.ptr_mut(), self.inner, result.as_mut_ptr(),) }
                    == NGX_OK as isize,
                "ngx_http_complex_value evaluation failed"
            );
        }
        Ok(result)
    }
}
