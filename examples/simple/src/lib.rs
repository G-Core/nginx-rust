/*
 * Copyright 2024 G-Core Innovations SARL
 */

use std::ffi::{c_char, c_void};

use nginx_derive::NginxConfig;
use nginx_module::{
    add_http_handler,
    nginx_version,
    ngx_command_t,
    ngx_conf_t,
    ngx_http_module_t,
    ngx_module_t,
    ngx_str_t,
    HttpHandler,
    HttpRequestAndContext,
    NgxConfig,
    NgxStr,
    NGX_DECLINED,
    NGX_HTTP_FORBIDDEN,
    NGX_HTTP_MODULE,
    NGX_RS_MODULE_SIGNATURE,
};

static mut COMMANDS: [ngx_command_t; NgxSimple::COMMANDS_COUNT] = NgxSimple::commands();

#[no_mangle]
pub static mut simple: ngx_module_t = ngx_module_t {
    ctx_index: usize::MAX,
    index: usize::MAX,
    name: "simple\0".as_ptr() as *mut c_char,
    spare0: 0,
    spare1: 0,
    version: nginx_version as usize,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const i8,
    ctx: unsafe { (&SIMPLE_CTX as *const ngx_http_module_t as *mut ngx_http_module_t).cast() },
    commands: unsafe { COMMANDS.as_mut_ptr() },
    type_: NGX_HTTP_MODULE as usize,
    init_master: None,
    init_module: None,
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,
    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

#[repr(C)]
#[derive(Default, NginxConfig)]
struct NgxSimple<'a> {
    deny_user_agent: NgxStr<'a>,
}

static mut SIMPLE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(simple_postconfig),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(NgxSimple::create),
    merge_loc_conf: Some(NgxSimple::merge),
};

unsafe extern "C" fn simple_postconfig(conf: *mut ngx_conf_t) -> isize {
    add_http_handler::<SimpleContext>(conf)
}

enum Decision {
    Allowed,
    Blocked,
}

#[derive(Default)]
struct SimpleContext {
    decision: Option<Decision>,
}

impl<'a> HttpHandler<'a> for SimpleContext {
    fn handle(req: &mut HttpRequestAndContext<'a, Self>) -> anyhow::Result<isize> {
        if !req.is_main() || req.internal() {
            return Ok(NGX_DECLINED as isize);
        }
        let Some(conf) = (unsafe { req.get_loc_config::<NgxSimple>(&simple) }) else {
            return Ok(NGX_DECLINED as isize);
        };

        if conf.deny_user_agent.is_empty() {
            return Ok(NGX_DECLINED as isize);
        }

        let (req, ctx) = req.split(unsafe { &simple })?;

        match ctx.decision {
            Some(Decision::Blocked) => {
                return Ok(NGX_HTTP_FORBIDDEN as isize);
            }
            Some(Decision::Allowed) => return Ok(NGX_DECLINED as isize),
            _ => (),
        }

        let user_agent = req.user_agent().unwrap_or_default().as_bytes();
        let denied_bytes = conf.deny_user_agent.as_bytes();
        if user_agent.len() >= denied_bytes.len()
            && &user_agent[..denied_bytes.len()] == denied_bytes
        {
            ctx.decision = Some(Decision::Blocked);
            Ok(NGX_HTTP_FORBIDDEN as isize)
        } else {
            ctx.decision = Some(Decision::Allowed);
            Ok(NGX_DECLINED as isize)
        }
    }
}
