/*
 * Copyright 2024 G-Core Innovations SARL
 */

use std::{marker::PhantomData, mem::MaybeUninit};

use crate::{
    bindings::{
        ngx_http_add_variable, ngx_http_variable_t, ngx_http_variable_value_t,
        ngx_variable_value_t, NGX_HTTP_VAR_CHANGEABLE, NGX_HTTP_VAR_NOCACHEABLE,
        NGX_HTTP_VAR_NOHASH,
    },
    ngx_http_request_t, ngx_str_t, HttpRequest, HttpRequestAndContext, IndexedVar, NgxConfig,
    NgxStr, NGX_ERROR, NGX_OK,
};

pub struct Variables<'a, 'pool, Context> {
    config: &'a NgxConfig<'pool>,
    _phantom: PhantomData<Context>,
}

pub struct Var;

pub struct NginxVar(ngx_http_variable_t);

impl NginxVar {
    pub(crate) unsafe fn new<'a>(raw: *mut ngx_http_variable_t) -> Option<&'a Self> {
        if raw.is_null() {
            None
        } else {
            Some(&*raw.cast())
        }
    }

    pub fn get(&self, req: &HttpRequest) -> NgxStr {
        unsafe {
            if let Some(g) = self.0.get_handler {
                let mut value: ngx_http_variable_value_t = MaybeUninit::zeroed().assume_init();
                g(req.ptr_mut(), &mut value, self.0.data);
                if value.valid() != 0 && value.not_found() == 0 {
                    NgxStr::from_raw(ngx_str_t {
                        len: value.len() as usize,
                        data: value.data,
                    })
                } else {
                    NgxStr::default()
                }
            } else {
                NgxStr::default()
            }
        }
    }

    pub fn set(&self, req: &HttpRequest, value: NgxStr) {
        unsafe {
            if let Some(s) = self.0.set_handler {
                let mut var_value: ngx_http_variable_value_t = MaybeUninit::zeroed().assume_init();
                var_value.set_valid(1);
                var_value.set_not_found(0);
                var_value.set_len(value.as_bytes().len() as u32);
                var_value.data = value.as_bytes().as_ptr().cast_mut();
                s(req.ptr_mut(), &mut var_value, self.0.data);
            } else if let Ok(value) = NgxStr::with_pool(req.pool(), value.as_bytes()) {
                req.set_indexed_var(IndexedVar(self.0.index as isize), value);
            }
        }
    }
}

pub trait VarAccess<'req, Context> {
    fn get(req: &mut HttpRequestAndContext<'req, Context>) -> Option<NgxStr<'req>>;
}

pub trait VarAccessMut<'req, Context>: VarAccess<'req, Context> {
    fn set(req: &mut HttpRequestAndContext<'req, Context>, value: Option<NgxStr<'req>>);
}

impl<'a, 'pool, Context: Default + 'a> Variables<'a, 'pool, Context> {
    pub fn new(config: &'a NgxConfig<'pool>) -> Self {
        Self {
            config,
            _phantom: PhantomData,
        }
    }

    pub fn add<T: VarAccess<'a, Context> + 'a>(&mut self, name: NgxStr) -> anyhow::Result<Var> {
        unsafe {
            let var = ngx_http_add_variable(
                self.config.ptr_mut_unsafe(),
                name.as_mut_ptr_unsafe(),
                (NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE) as usize,
            );
            anyhow::ensure!(!var.is_null());
            (*var).get_handler = Some(getter_fn::<Context, T>);
        }
        Ok(Var)
    }

    pub fn add_changeable<T: VarAccess<'a, Context> + 'a>(
        &mut self,
        name: NgxStr,
    ) -> anyhow::Result<Var> {
        unsafe {
            let var = ngx_http_add_variable(
                self.config.ptr_mut_unsafe(),
                name.as_mut_ptr_unsafe(),
                (NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_CHANGEABLE) as usize,
            );
            anyhow::ensure!(!var.is_null());
            (*var).get_handler = Some(getter_fn::<Context, T>);
        }
        Ok(Var)
    }

    pub fn add_mut<T: VarAccessMut<'a, Context> + 'a>(
        &mut self,
        name: NgxStr,
    ) -> anyhow::Result<Var> {
        unsafe {
            let var = ngx_http_add_variable(
                self.config.ptr_mut_unsafe(),
                name.as_mut_ptr_unsafe(),
                (NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_CHANGEABLE) as usize,
            );
            anyhow::ensure!(!var.is_null());
            (*var).get_handler = Some(getter_fn::<Context, T>);
            (*var).set_handler = Some(setter_fn::<Context, T>);
        }
        Ok(Var)
    }
}

unsafe extern "C" fn getter_fn<'a, Context: Default + 'a, T: VarAccess<'a, Context> + 'a>(
    req: *mut ngx_http_request_t,
    value: *mut ngx_variable_value_t,
    _data: usize,
) -> isize {
    let Some(req) = HttpRequestAndContext::from_raw(req) else {
        (*value).set_not_found(1);
        return NGX_OK as isize;
    };
    if let Some(v) = T::get(req) {
        let Ok(data) = req.pool().alloc_bytes(v.inner().len) else {
            req.log().error(format!(
                "Allocation failed for variable data, {} bytes",
                v.inner().len
            ));
            return NGX_ERROR as isize;
        };
        data.copy_from_slice(v.as_bytes());
        (*value).data = data.as_mut_ptr();
        (*value).set_len(data.len() as u32);
        (*value).set_not_found(0);
        (*value).set_valid(1);
    } else {
        (*value).set_not_found(1);
    }
    NGX_OK as isize
}

unsafe extern "C" fn setter_fn<'a, Context: Default + 'a, T: VarAccessMut<'a, Context> + 'a>(
    req: *mut ngx_http_request_t,
    value: *mut ngx_variable_value_t,
    _data: usize,
) {
    if let Some(req) = HttpRequestAndContext::from_raw(req) {
        if let Some(v) = value.as_ref() {
            let s = if v.not_found() == 0 && v.valid() != 0 {
                Some(NgxStr::new(std::slice::from_raw_parts(
                    v.data,
                    v.len() as usize,
                )))
            } else {
                None
            };

            T::set(req, s);
        }
    }
}
