mod bindings;
use std::{
    ffi::{CStr, CString},
    str::FromStr,
};

pub use bindings::{
    nginx_version, ngx_command_t, ngx_conf_t, ngx_cycle_t, ngx_http_conf_ctx_t, ngx_http_module_t,
    ngx_http_request_t, ngx_module_t, ngx_str_t, NGX_CONF_TAKE1, NGX_DECLINED, NGX_ERROR,
    NGX_HTTP_FORBIDDEN, NGX_HTTP_LOC_CONF, NGX_HTTP_MAIN_CONF, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF,
    NGX_HTTP_TEMPORARY_REDIRECT, NGX_LOG_ERR, NGX_OK, NGX_RS_HTTP_LOC_CONF_OFFSET,
    NGX_RS_MODULE_SIGNATURE,
};
use bindings::{
    ngx_array_push, ngx_cycle, ngx_http_core_main_conf_t, ngx_http_core_module,
    ngx_http_handler_pt, ngx_http_phases_NGX_HTTP_ACCESS_PHASE,
};

mod ngx_str;
use log::ngx_log_error;
pub use ngx_str::NgxStr;

mod complex_value;
pub use complex_value::ComplexValue;

/*
* Copyright 2023 G-Core Innovations SARL
*/

mod http_request;
pub use http_request::{HttpRequest, HttpRequestAndContext};

mod pool;
pub use pool::Pool;

mod md5;
pub use md5::{Md5, MD5_DIGEST_LENGTH};

mod connection;

mod log;
pub use log::Log;

mod var;
pub use var::{VarAccess, VarAccessMut, Variables};

mod wrappers;
pub use wrappers::{hex_dump, NgxConfig};

pub trait Config {
    fn commands() -> &'static mut [ngx_command_t];
}

pub trait ConfigValue<'a>: Sized {
    fn config_directive(
        &mut self,
        conf: &'a mut NgxConfig,
        value: NgxStr<'a>,
    ) -> anyhow::Result<()>;
    fn merge(&mut self, other: &Self);
}

impl<'a> ConfigValue<'a> for NgxStr<'a> {
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        value: NgxStr<'a>,
    ) -> anyhow::Result<()> {
        *self = value;
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        if self.is_empty() {
            *self = *other;
        }
    }
}

impl<'a, T> ConfigValue<'a> for Option<T>
where
    T: FromStr + Clone,
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        value: NgxStr<'a>,
    ) -> anyhow::Result<()> {
        *self = Some(unsafe { value.as_str_unchecked() }.parse()?);
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        if self.is_none() {
            *self = other.clone();
        }
    }
}

impl<'a, T> ConfigValue<'a> for Vec<T>
where
    T: FromStr + Clone,
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        value: NgxStr<'a>,
    ) -> anyhow::Result<()> {
        self.push(unsafe { value.as_str_unchecked() }.parse()?);
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        self.extend_from_slice(&other[..]);
    }
}

impl<'a> ConfigValue<'a> for Vec<NgxStr<'a>> {
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        value: NgxStr<'a>,
    ) -> anyhow::Result<()> {
        self.push(value);
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        self.extend_from_slice(&other[..]);
    }
}

pub const NGX_CONF_OK: *mut i8 = std::ptr::null_mut();

pub const NGX_RS_NULL_COMMAND: ngx_command_t = ngx_command_t {
    name: NgxStr::null().inner(),
    type_: 0,
    set: None,
    conf: 0,
    offset: 0,
    post: std::ptr::null_mut(),
};

pub trait HttpHandler<'a>: Sized {
    fn handle(req: &mut HttpRequestAndContext<'a, Self>) -> anyhow::Result<isize>;
}

///
/// # Safety
///  
///  `conf` should be a valid ngx_conf_t pointer
///
pub unsafe fn add_http_handler<'a, H: HttpHandler<'a> + Default + 'a>(
    conf: *mut ngx_conf_t,
) -> isize {
    let cmcf = (*(*((*conf).ctx as *mut ngx_http_conf_ctx_t))
        .main_conf
        .add(ngx_http_core_module.ctx_index)) as *mut ngx_http_core_main_conf_t;

    let h = ngx_array_push(
        &mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers,
    ) as *mut ngx_http_handler_pt;
    if h.is_null() {
        NGX_ERROR as isize
    } else {
        *h = Some(ngx_http_generic_handler::<H>);
        NGX_OK as isize
    }
}

unsafe extern "C" fn ngx_http_generic_handler<'a, H: HttpHandler<'a> + Default + 'a>(
    req: *mut ngx_http_request_t,
) -> isize {
    let Some(req) = HttpRequestAndContext::from_raw(req) else {
        // Logging to ngx_cycle->log as there is no request if it's null...
        ngx_log_error(
            NGX_LOG_ERR as usize,
            (*ngx_cycle).log,
            0,
            CStr::from_bytes_with_nul_unchecked(b"Null http request pointer\0"),
        );
        return NGX_ERROR as isize;
    };
    match <H as HttpHandler>::handle(req) {
        Ok(result) => result,
        Err(e) => {
            if let Ok(err_msg) = CString::new(e.to_string()) {
                ngx_log_error(NGX_LOG_ERR as usize, (*ngx_cycle).log, 0, &err_msg);
            }
            NGX_ERROR as isize
        }
    }
}
