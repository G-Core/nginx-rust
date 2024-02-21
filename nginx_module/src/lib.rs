/*
 * Copyright 2024 G-Core Innovations SARL
 */

mod bindings;
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    str::FromStr,
    sync::Mutex,
};

pub use bindings::{
    nginx_version, ngx_buf_t, ngx_chain_add_copy, ngx_chain_t, ngx_command_t, ngx_conf_t,
    ngx_current_msec, ngx_cycle_t, ngx_http_conf_ctx_t, ngx_http_module_t,
    ngx_http_request_body_filter_pt, ngx_http_request_t, ngx_module_t, ngx_str_t, NGX_AGAIN,
    NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_DECLINED, NGX_ERROR, NGX_HTTP_FORBIDDEN, NGX_HTTP_LOC_CONF,
    NGX_HTTP_MAIN_CONF, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF, NGX_HTTP_TEMPORARY_REDIRECT,
    NGX_LOG_ERR, NGX_OK, NGX_RS_HTTP_LOC_CONF_OFFSET, NGX_RS_MODULE_SIGNATURE,
};
use bindings::{
    ngx_array_push, ngx_cycle, ngx_event_t, ngx_event_timer_rbtree, ngx_http_core_main_conf_t,
    ngx_http_core_module, ngx_http_handler_pt, ngx_http_phases_NGX_HTTP_ACCESS_PHASE,
    ngx_http_top_request_body_filter, ngx_queue_t, ngx_rbtree_delete, ngx_rbtree_insert,
};

mod ngx_str;
use log::ngx_log_error;
pub use ngx_str::NgxStr;

mod complex_value;
pub use complex_value::ComplexValue;

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
use strum::EnumString;
pub use var::{VarAccess, VarAccessMut, Variables};

mod wrappers;
pub use wrappers::{hex_dump, IndexedVar, NgxConfig};

mod unix_socket;
pub use unix_socket::{Disconnected, UnixSocket};

mod timer;
pub use timer::Timer;

pub trait Config {
    fn commands() -> &'static mut [ngx_command_t];
}

pub enum Arity {
    OneArg,
    TwoArgs,
}

impl Arity {
    pub const fn as_nginx_type(&self) -> u32 {
        match self {
            Arity::OneArg => NGX_CONF_TAKE1,
            Arity::TwoArgs => NGX_CONF_TAKE2,
        }
    }
}

pub trait ConfigValue<'a>: Sized {
    fn config_directive(
        &mut self,
        conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()>;
    fn merge(&mut self, other: &Self);
    const ARITY: Arity = Arity::OneArg;
}

impl<'a> ConfigValue<'a> for NgxStr<'a> {
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        *self = values[0];
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
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        *self = Some(unsafe { values[0].as_str_unchecked() }.parse()?);
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        if self.is_none() {
            *self = other.clone();
        }
    }
}

pub trait ConfigSingleValue: Sized {
    fn from_ngx_str(value: NgxStr) -> anyhow::Result<Self>;
}

impl<'a, T> ConfigValue<'a> for Vec<T>
where
    T: ConfigSingleValue + Clone,
{
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        self.push(T::from_ngx_str(values[0])?);
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
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        self.push(values[0]);
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        self.extend_from_slice(&other[..]);
    }
}

impl<'a> ConfigValue<'a> for Vec<(NgxStr<'a>, NgxStr<'a>)> {
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        self.push((values[0], values[1]));
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        self.extend_from_slice(&other[..]);
    }

    const ARITY: Arity = Arity::TwoArgs;
}

impl<'a> ConfigValue<'a> for HashMap<NgxStr<'a>, NgxStr<'a>> {
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        self.insert(values[0], values[1]);
        Ok(())
    }

    fn merge(&mut self, parent: &Self) {
        for (key, value) in parent {
            self.entry(*key).or_insert(*value);
        }
    }

    const ARITY: Arity = Arity::TwoArgs;
}

impl<'a> ConfigValue<'a> for HashMap<NgxStr<'a>, Vec<NgxStr<'a>>> {
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        self.entry(values[0]).or_default().push(values[1]);
        Ok(())
    }

    fn merge(&mut self, parent: &Self) {
        for (key, value) in parent {
            self.entry(*key).or_default().extend_from_slice(value)
        }
    }

    const ARITY: Arity = Arity::TwoArgs;
}

#[derive(Copy, Clone, EnumString, Eq, PartialEq, Debug)]
#[strum(serialize_all = "lowercase")]
pub enum Enabled {
    On,
    Off,
}

impl<'a> ConfigValue<'a> for HashMap<NgxStr<'a>, Enabled> {
    fn config_directive(
        &mut self,
        _conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        self.insert(values[0], unsafe { values[1].as_str_unchecked() }.parse()?);
        Ok(())
    }

    fn merge(&mut self, parent: &Self) {
        for (key, value) in parent {
            self.entry(*key).or_insert(*value);
        }
    }

    const ARITY: Arity = Arity::TwoArgs;
}

impl<'a> ConfigValue<'a> for HashMap<NgxStr<'a>, ComplexValue<'a>> {
    fn config_directive(
        &mut self,
        conf: &'a mut NgxConfig,
        values: &[NgxStr<'a>],
    ) -> anyhow::Result<()> {
        let mut complex = ComplexValue::default();
        complex.config_directive(conf, &values[1..])?;
        self.insert(values[0], complex);
        Ok(())
    }

    fn merge(&mut self, parent: &Self) {
        for (key, value) in parent {
            self.entry(*key).or_insert(*value);
        }
    }

    const ARITY: Arity = Arity::TwoArgs;
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

pub trait HttpRequestBodyHandler<'a>: Sized {
    fn next_handler() -> &'a Mutex<ngx_http_request_body_filter_pt>;
    fn handle(
        req: &mut HttpRequestAndContext<'a, Self>,
        buf: *mut ngx_chain_t,
    ) -> anyhow::Result<isize>;
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

pub fn add_request_body_handler<'a, H: HttpRequestBodyHandler<'a> + Default + 'a>() {
    unsafe {
        if let Ok(mut handler) = H::next_handler().lock() {
            *handler = ngx_http_top_request_body_filter
        }
        ngx_http_top_request_body_filter = Some(body_handler::<'a, H>);
    }
}

unsafe extern "C" fn body_handler<'a, H: HttpRequestBodyHandler<'a> + Default + 'a>(
    req: *mut ngx_http_request_t,
    buf: *mut ngx_chain_t,
) -> isize {
    if let Some(req) = HttpRequestAndContext::from_raw(req) {
        match H::handle(req, buf) {
            Ok(result) => {
                if result != NGX_OK as isize {
                    if result == NGX_AGAIN as isize {
                        return NGX_OK as isize;
                    }
                    return result;
                }
            }
            Err(e) => {
                if let Ok(err_msg) = CString::new(e.to_string()) {
                    ngx_log_error(NGX_LOG_ERR as usize, (*ngx_cycle).log, 0, &err_msg);
                }
                return NGX_ERROR as isize;
            }
        }
    }
    if let Ok(next) = H::next_handler().lock() {
        if let Some(next) = *next {
            next(req, buf)
        } else {
            NGX_OK as isize
        }
    } else {
        ngx_log_error(
            NGX_LOG_ERR as usize,
            (*ngx_cycle).log,
            0,
            CStr::from_bytes_with_nul_unchecked(b"Poisoned lock in request body handler\0"),
        );
        NGX_ERROR as isize
    }
}

///
/// # Safety
///  
///  `ev` should be a valid ngx_event_t pointer
///
pub unsafe fn ngx_event_del_timer(ev: *mut ngx_event_t) {
    ngx_rbtree_delete(&mut ngx_event_timer_rbtree, &mut (*ev).timer);
    (*ev).set_timer_set(0);
}

///
/// # Safety
///  
///  `ev` should be a valid ngx_event_t pointer
///
pub unsafe fn ngx_event_add_timer(ev: *mut ngx_event_t, timeout_ms: usize) {
    let key = ngx_current_msec + timeout_ms;

    if (*ev).timer_set() != 0 {
        let diff = key as isize - (*ev).timer.key as isize;
        if diff.abs() < 300
        /* milliseconds */
        {
            // do nothing
            return;
        }

        ngx_event_del_timer(ev);
    }

    (*ev).timer.key = key;
    ngx_rbtree_insert(&mut ngx_event_timer_rbtree, &mut (*ev).timer);
    (*ev).set_timer_set(1);
}

pub(crate) unsafe fn ngx_post_event(ev: *mut ngx_event_t, q: *mut ngx_queue_t) {
    if (*ev).posted() == 0 {
        (*ev).set_posted(1);
        ngx_queue_insert_tail(q, &mut (*ev).queue);
    }
}

pub(crate) unsafe fn ngx_queue_insert_tail(h: *mut ngx_queue_t, x: *mut ngx_queue_t) {
    (*x).next = (*h).next;
    (*(*x).next).prev = x;
    (*x).prev = h;
    (*h).next = x
}
