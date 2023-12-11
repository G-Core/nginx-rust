/*
 * Copyright 2023 G-Core Innovations SARL
 */

use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

#[cfg(not(nginx_version_1023000))]
use crate::{
    bindings::{ngx_array_push, ngx_array_t, NGX_DECLINED, NGX_OK},
    wrappers::array_init,
};
use crate::{
    bindings::{
        ngx_http_get_indexed_variable, ngx_http_parse_multi_header_lines, ngx_http_request_t,
        ngx_list_push, ngx_list_t, ngx_module_t, ngx_table_elt_t,
    },
    ngx_str_t,
    wrappers::IndexedVar,
};
use crate::{connection::Connection, Log};

use super::{NgxStr, Pool};

pub struct HttpRequestAndContext<'a, Ctx>(ngx_http_request_t, PhantomData<&'a Ctx>);

pub struct HttpRequest<'a>(ngx_http_request_t, PhantomData<&'a ()>);

impl<'a, Ctx: Default> HttpRequestAndContext<'a, Ctx> {
    ///
    /// # Safety
    ///  
    ///  `ptr` should be a valid ngx_http_request_t pointer
    ///
    pub unsafe fn from_raw<'b>(ptr: *mut ngx_http_request_t) -> Option<&'b mut Self> {
        (ptr as *mut Self).as_mut()
    }

    pub fn split(
        &mut self,
        module: &ngx_module_t,
    ) -> anyhow::Result<(&mut HttpRequest<'a>, &mut Ctx)> {
        unsafe {
            let req = &mut *(&mut self.0 as *mut ngx_http_request_t as *mut HttpRequest);
            let ptr = self.0.ctx.add(module.ctx_index);
            let ctx = if (*ptr).is_null() {
                let pool = Pool::from_raw(self.0.pool);
                let ctx = pool.alloc()?;

                *ptr = (ctx as *mut Ctx).cast();
                ctx
            } else {
                &mut *(*ptr).cast()
            };
            Ok((req, ctx))
        }
    }
}

impl<'a, Ctx> Deref for HttpRequestAndContext<'a, Ctx> {
    type Target = HttpRequest<'a>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(&self.0 as *const ngx_http_request_t as *const HttpRequest) }
    }
}

impl<'a, Ctx> DerefMut for HttpRequestAndContext<'a, Ctx> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(&mut self.0 as *mut ngx_http_request_t as *mut HttpRequest) }
    }
}

impl<'a> HttpRequest<'a> {
    pub fn get_loc_config<'b, Config>(&self, module: &ngx_module_t) -> Option<&'b Config> {
        unsafe {
            let conf = (*(*self.0.main).loc_conf.add(module.ctx_index)) as *const Config;
            conf.as_ref()
        }
    }

    pub fn is_main(&self) -> bool {
        std::ptr::eq(&self.0, self.0.main)
    }

    pub fn internal(&self) -> bool {
        self.0.internal() != 0
    }

    pub fn pool(&self) -> &'a Pool {
        unsafe { Pool::from_raw(self.0.pool) }
    }

    pub(crate) unsafe fn ptr_mut(&self) -> *mut ngx_http_request_t {
        (&self.0 as *const ngx_http_request_t).cast_mut()
    }

    pub fn connection(&self) -> Option<&Connection> {
        unsafe { Connection::from_raw(self.0.connection) }
    }

    pub fn log(&self) -> &Log {
        unsafe { Log::new((*self.0.connection).log) }
    }

    pub fn user_agent(&self) -> Option<NgxStr> {
        unsafe {
            let user_agent = self.0.headers_in.user_agent;
            if user_agent.is_null() {
                None
            } else {
                Some(NgxStr::from_raw((*self.0.headers_in.user_agent).value))
            }
        }
    }

    #[cfg(not(nginx_version_1023000))]
    pub fn cookie(&self, name: NgxStr) -> Option<NgxStr<'a>> {
        let mut cookie = NgxStr::default();
        if unsafe {
            ngx_http_parse_multi_header_lines(
                (&self.0.headers_in.cookies as *const ngx_array_t).cast_mut(),
                name.as_mut_ptr_unsafe(),
                cookie.as_mut_ptr(),
            )
        } == NGX_DECLINED as isize
        {
            None
        } else {
            Some(cookie)
        }
    }

    #[cfg(nginx_version_1023000)]
    pub fn cookie(&self, name: NgxStr) -> Option<NgxStr<'a>> {
        let mut cookie = NgxStr::default();
        if unsafe {
            ngx_http_parse_multi_header_lines(
                (&self.0 as *const ngx_http_request_t).cast_mut(),
                self.0.headers_in.cookie,
                name.as_mut_ptr_unsafe(),
                cookie.as_mut_ptr(),
            )
            .is_null()
        } {
            None
        } else {
            Some(cookie)
        }
    }

    pub fn set_cookie(&self, data: NgxStr<'a>) -> anyhow::Result<()> {
        unsafe {
            let cookie =
                ngx_list_push(&self.0.headers_out.headers as *const ngx_list_t as *mut ngx_list_t)
                    as *mut ngx_table_elt_t;
            anyhow::ensure!(!cookie.is_null());
            let cookie = &mut *cookie;
            cookie.hash = 1;
            cookie.key = NgxStr::new_from_array(b"Set-Cookie").inner();
            cookie.value = data.inner();

            Ok(())
        }
    }

    pub fn set_location(&mut self, data: NgxStr<'a>) -> anyhow::Result<()> {
        unsafe {
            let value =
                ngx_list_push(&self.0.headers_out.headers as *const ngx_list_t as *mut ngx_list_t)
                    as *mut ngx_table_elt_t;
            anyhow::ensure!(!value.is_null());
            let value = &mut *value;
            value.hash = 1;
            value.key = NgxStr::new_from_array(b"Location").inner();
            value.value = data.inner();

            self.0.headers_out.location = value;

            Ok(())
        }
    }

    pub fn unparsed_uri(&self) -> NgxStr {
        unsafe { NgxStr::from_raw(self.0.unparsed_uri) }
    }

    pub fn uri_args(&self) -> NgxStr {
        unsafe { NgxStr::from_raw(self.0.args) }
    }

    pub fn server(&self) -> NgxStr {
        unsafe { NgxStr::from_raw(self.0.headers_in.server) }
    }

    pub fn is_ssl(&self) -> bool {
        unsafe { !(*self.0.connection).ssl.is_null() }
    }

    pub fn clear_accept_ranges(&mut self) {
        unsafe {
            self.0.set_allow_ranges(0);
            if !self.0.headers_out.accept_ranges.is_null() {
                (*self.0.headers_out.accept_ranges).hash = 0;
                self.0.headers_out.accept_ranges = std::ptr::null_mut();
            }
        }
    }

    pub fn clear_last_modified(&mut self) {
        unsafe {
            self.0.headers_out.last_modified_time = -1;
            if !self.0.headers_out.last_modified.is_null() {
                (*self.0.headers_out.last_modified).hash = 0;
                self.0.headers_out.last_modified = std::ptr::null_mut();
            }
        }
    }

    pub fn clear_content_length(&mut self) {
        unsafe {
            self.0.headers_out.content_length_n = -1;
            if !self.0.headers_out.content_length.is_null() {
                (*self.0.headers_out.content_length).hash = 0;
                self.0.headers_out.content_length = std::ptr::null_mut();
            }
        }
    }

    pub fn clear_etag(&mut self) {
        unsafe {
            if !self.0.headers_out.etag.is_null() {
                (*self.0.headers_out.etag).hash = 0;
                self.0.headers_out.etag = std::ptr::null_mut();
            }
        }
    }

    pub fn set_no_cache(&mut self) -> anyhow::Result<()> {
        unsafe {
            let mut e = self.0.headers_out.expires;
            if e.is_null() {
                e = ngx_list_push(&mut self.0.headers_out.headers) as *mut ngx_table_elt_t;
                anyhow::ensure!(!e.is_null());
            }
            self.0.headers_out.expires = e;
            (*e).hash = 1;
            (*e).key = NgxStr::new_from_array(b"Expires").inner();
            (*e).value = NgxStr::new_from_array(b"Thu, 01 Jan 1970 00:00:01 GMT").inner();

            let mut cc;
            #[cfg(not(nginx_version_1023000))]
            {
                let mut ccp = self.0.headers_out.cache_control.elts as *mut *mut ngx_table_elt_t;
                if ccp.is_null() {
                    anyhow::ensure!(
                        array_init(
                            &mut self.0.headers_out.cache_control,
                            self.0.pool,
                            1,
                            std::mem::size_of::<*mut ngx_table_elt_t>()
                        ) == NGX_OK as isize
                    );
                    ccp = ngx_array_push(&mut self.0.headers_out.cache_control).cast();
                    anyhow::ensure!(!ccp.is_null());
                    cc = ngx_list_push(&mut self.0.headers_out.headers) as *mut ngx_table_elt_t;
                    anyhow::ensure!(!cc.is_null());
                    (*cc).hash = 1;
                    (*cc).key = NgxStr::new_from_array(b"Cache-Control").inner();
                    *ccp = cc;
                } else {
                    let slice =
                        std::slice::from_raw_parts_mut(ccp, self.0.headers_out.cache_control.nelts);
                    for s in &mut slice[1..] {
                        (**s).hash = 0;
                    }
                    cc = slice[0];
                };
            }
            #[cfg(nginx_version_1023000)]
            {
                cc = self.0.headers_out.cache_control;
                if cc.is_null() {
                    cc = ngx_list_push(&mut self.0.headers_out.headers) as *mut ngx_table_elt_t;
                    anyhow::ensure!(!cc.is_null());
                    self.0.headers_out.cache_control = cc;
                    (*cc).next = std::ptr::null_mut();
                    (*cc).hash = 1;
                    (*cc).key = NgxStr::new_from_array(b"Cache-Control").inner();
                } else {
                    let mut iter = (*cc).next;
                    while !iter.is_null() {
                        (*iter).hash = 0;
                        iter = (*iter).next;
                    }
                    (*cc).next = std::ptr::null_mut();
                }
            }
            (*cc).value = NgxStr::new_from_array(b"no-cache").inner();
        }
        Ok(())
    }

    pub fn get_indexed_var(&self, var: IndexedVar) -> Option<NgxStr> {
        unsafe {
            let var_value = ngx_http_get_indexed_variable(
                &self.0 as *const ngx_http_request_t as *mut ngx_http_request_t,
                var.0 as usize,
            );
            if var_value.is_null() {
                None
            } else {
                let var_value = &*var_value;
                if var_value.valid() != 0 && var_value.not_found() == 0 {
                    Some(NgxStr::from_raw(ngx_str_t {
                        len: var_value.len() as usize,
                        data: var_value.data,
                    }))
                } else {
                    None
                }
            }
        }
    }

    pub fn set_indexed_var(&mut self, var: IndexedVar, value: NgxStr) {
        unsafe {
            let var_value = ngx_http_get_indexed_variable(
                &self.0 as *const ngx_http_request_t as *mut ngx_http_request_t,
                var.0 as usize,
            );
            if !var_value.is_null() {
                let var_value = &mut *var_value;
                var_value.set_not_found(0);
                var_value.set_valid(1);
                var_value.set_len(value.inner().len as u32);
                var_value.data = value.inner().data;
            }
        }
    }

    pub fn accept_encoding(&self) -> Option<NgxStr<'a>> {
        let accept_enconding_entry = self.0.headers_in.accept_encoding;
        if accept_enconding_entry.is_null() {
            None
        } else {
            unsafe {
                let accept_encoding = (*accept_enconding_entry).value;
                Some(NgxStr::from_raw(accept_encoding))
            }
        }
    }
}
