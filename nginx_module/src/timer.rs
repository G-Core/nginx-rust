use std::{marker::PhantomData, mem::MaybeUninit, pin::Pin};

use crate::{
    bindings::{ngx_cycle, ngx_event_t, ngx_exiting, ngx_quit, ngx_terminate},
    ngx_event_add_timer, ngx_event_del_timer,
};

pub struct Timer<HandlerFn> {
    event: Pin<Box<ngx_event_t>>, // Need to have the timer at a fixed address in memory
    _phantom: PhantomData<HandlerFn>,
}

impl<HandlerFn> Drop for Timer<HandlerFn> {
    fn drop(&mut self) {
        if !self.event.data.is_null() {
            let data_ptr: *mut Data<HandlerFn> = self.event.data.cast();
            let data = unsafe { Box::from_raw(data_ptr) };
            std::mem::drop(data);
            self.event.data = std::ptr::null_mut();
        }

        unsafe {
            if self.event.timer_set() != 0 {
                ngx_event_del_timer(&mut *self.event.as_mut());
            }
        }
    }
}

struct Data<HandlerFn> {
    handler: HandlerFn,
    interval_msec: usize,
}

impl<HandlerFn: FnMut()> Timer<HandlerFn> {
    pub fn start(handler: HandlerFn, interval_msec: usize) -> Self {
        let mut event: Pin<Box<ngx_event_t>> =
            Box::pin(unsafe { MaybeUninit::zeroed().assume_init() });
        event.handler = Some(timer_fn::<HandlerFn>);
        let data = Data {
            handler,
            interval_msec,
        };
        event.data = Box::into_raw(Box::new(data)).cast();
        event.log = unsafe { (*ngx_cycle).log };

        unsafe { ngx_event_add_timer(&mut *event, interval_msec) };

        Self {
            event,
            _phantom: PhantomData,
        }
    }
}

unsafe extern "C" fn timer_fn<HandlerFn: FnMut()>(ev: *mut ngx_event_t) {
    if !(*ev).data.is_null() {
        let data: *mut Data<HandlerFn> = (*ev).data.cast();
        ((*data).handler)();
        if (*ev).timer_set() == 0 && ngx_quit == 0 && ngx_exiting == 0 && ngx_terminate == 0 {
            ngx_event_add_timer(ev, (*data).interval_msec);
        }
    }
}
