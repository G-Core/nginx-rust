/*
* Copyright 2023 G-Core Innovations SARL
*/

use std::ffi::{CStr, CString};

use crate::{
    bindings::{ngx_err_t, ngx_log_error_core, ngx_log_t},
    NGX_LOG_ERR,
};

/// 
/// # Safety
///  
///  `log` should be a valid ngx_log_t pointer
///
pub(crate) unsafe fn ngx_log_error(level: usize, log: *mut ngx_log_t, err: ngx_err_t, msg: &CStr) {
    if (*log).log_level >= level {
        ngx_log_error_core(level, log, err, msg.as_ptr())
    }
}

/// Abstraction over the log feature
pub struct Log(ngx_log_t);

impl Log {
    ///
    /// # Safety
    /// log should be a valid ngx_log_t pointer
    /// Also, this can assign an arbitrary lifetime, different than the real one
    ///
    pub unsafe fn new<'a>(log: *const ngx_log_t) -> &'a Self {
        &*log.cast()
    }

    pub fn error(&self, msg: String) {
        if let Ok(err_msg) = CString::new(msg) {
            unsafe {
                ngx_log_error(
                    NGX_LOG_ERR as usize,
                    (&self.0 as *const ngx_log_t).cast_mut(),
                    0,
                    &err_msg,
                )
            };
        }
    }
}
