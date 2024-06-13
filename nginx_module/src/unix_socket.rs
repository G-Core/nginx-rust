use std::{
    borrow::Cow, cell::RefCell, collections::VecDeque, marker::PhantomPinned, mem::MaybeUninit,
    os::unix::ffi::OsStrExt, path::Path, pin::Pin,
};

use libc::{c_void, sockaddr_un};

use crate::{
    bindings::{
        ngx_close_connection, ngx_connection_t, ngx_cycle, ngx_event_actions,
        ngx_event_connect_peer, ngx_event_t, ngx_exiting, ngx_handle_read_event,
        ngx_handle_write_event, ngx_log_t, ngx_peer_connection_t, ngx_quit, ngx_terminate,
        NGX_AGAIN, NGX_RS_WRITE_EVENT,
    },
    ngx_event_add_timer, ngx_event_del_timer, NgxStr, NGX_OK,
};

pub struct UnixSocket(Pin<Box<Inner>>);

enum State {
    Connected {
        conn: *mut ngx_connection_t,
        buffers: WriteBuffers,
    },
    WaitServerHandshake {
        conn: *mut ngx_connection_t,
        buffers: WriteBuffers,
    },
    Disconnected {
        event: Box<ngx_event_t>,
    },
}

struct Inner {
    state: RefCell<State>,
    on_read: Box<RefCell<ReadFn>>,
    check_handshake: Box<RefCell<ValidateFn>>,
    after_handshake: Box<RefCell<dyn FnMut() -> Vec<u8> + 'static>>,
    handshake_msg: Vec<u8>,
    path: String,
    name: Cow<'static, [u8]>,
    dummy_log: Box<ngx_log_t>,
    _phantom: PhantomPinned,
}

type ReadFn = dyn FnMut(&[u8]) -> Vec<u8>;
type ValidateFn = dyn FnMut(&[u8]) -> anyhow::Result<()>;

#[derive(Default)]
struct WriteBuffers {
    buffers: VecDeque<WriteBuffer>,
}

struct WriteBuffer {
    data: Box<[u8]>,
    start: u32,
    end: u32,
}

const TIMEOUT_MS: usize = 500;

impl UnixSocket {
    pub fn connect(
        path: String,
        name: Cow<'static, [u8]>,
        read_event: impl FnMut(&[u8]) -> Vec<u8> + 'static,
        handshake_msg: Vec<u8>,
        check_server_handshake: impl FnMut(&[u8]) -> anyhow::Result<()> + 'static,
        after_handshake: impl FnMut() -> Vec<u8> + 'static,
    ) -> Self {
        let mut dummy_log: Box<ngx_log_t> =
            Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        dummy_log.writer = Some(dummy_log_fn);
        if unsafe { ngx_quit != 0 || ngx_exiting != 0 || ngx_terminate != 0 } {
            let state = unsafe {
                let mut ev: Box<ngx_event_t> = Box::new(MaybeUninit::zeroed().assume_init());
                ev.handler = Some(on_reconnect_timeout);
                ev.log = (*ngx_cycle).log;

                State::Disconnected { event: ev }
            };
            let inner = Inner {
                state: RefCell::new(state),
                on_read: Box::new(RefCell::new(read_event)),
                check_handshake: Box::new(RefCell::new(check_server_handshake)),
                after_handshake: Box::new(RefCell::new(after_handshake)),
                handshake_msg,
                path,
                name,
                dummy_log,
                _phantom: PhantomPinned,
            };
            return Self(Box::pin(inner));
        }

        let state = match State::try_connect(&path, &name, &mut *dummy_log) {
            Some(conn) => {
                let mut buffers = WriteBuffers::default();
                buffers.push(&handshake_msg);
                match unsafe { buffers.send(conn) } {
                    Ok(()) => State::WaitServerHandshake { conn, buffers },
                    Err(_) => unsafe {
                        let mut ev: Box<ngx_event_t> =
                            Box::new(MaybeUninit::zeroed().assume_init());
                        ev.handler = Some(on_reconnect_timeout);
                        ev.log = (*ngx_cycle).log;
                        ngx_event_add_timer(&mut *ev, TIMEOUT_MS);
                        State::Disconnected { event: ev }
                    },
                }
            }
            None => unsafe {
                let mut ev: Box<ngx_event_t> = Box::new(MaybeUninit::zeroed().assume_init());
                ev.handler = Some(on_reconnect_timeout);
                ev.log = (*ngx_cycle).log;
                ngx_event_add_timer(&mut *ev, TIMEOUT_MS);
                State::Disconnected { event: ev }
            },
        };

        let inner = Inner {
            state: RefCell::new(state),
            on_read: Box::new(RefCell::new(read_event)),
            check_handshake: Box::new(RefCell::new(check_server_handshake)),
            after_handshake: Box::new(RefCell::new(after_handshake)),
            handshake_msg,
            path,
            name,
            dummy_log,
            _phantom: PhantomPinned,
        };

        let inner = Box::pin(inner);
        match &mut *inner.state.borrow_mut() {
            State::WaitServerHandshake { conn, .. } => unsafe {
                (**conn).data = (&*inner as *const Inner as *mut Inner).cast();
                (*(**conn).write).handler = Some(on_write);
                (*(**conn).read).handler = Some(on_read);
            },
            State::Connected { conn, .. } => unsafe {
                (**conn).data = (&*inner as *const Inner as *mut Inner).cast();
                (*(**conn).write).handler = Some(on_write);
                (*(**conn).read).handler = Some(on_read);
            },
            State::Disconnected { event } => {
                event.data = (&*inner as *const Inner as *mut Inner).cast();
                (inner.after_handshake.borrow_mut())(); // discard send data, it is disconnected
            }
        }

        Self(inner)
    }

    pub fn disconnected(&self) -> bool {
        matches!(&*self.0.state.borrow_mut(), State::Disconnected { .. })
    }

    pub fn stop(&self) {
        unsafe {
            // create a dummy event, but don't schedule it
            let mut dummy_ev: Box<ngx_event_t> = Box::new(MaybeUninit::zeroed().assume_init());
            dummy_ev.handler = None;
            dummy_ev.log = (*ngx_cycle).log;
            *self.0.state.borrow_mut() = State::Disconnected { event: dummy_ev }
        }
    }
}

impl State {
    fn try_connect(path: &str, name: &[u8], log: *mut ngx_log_t) -> Option<*mut ngx_connection_t> {
        let mut sockaddr = sockaddr_un {
            sun_family: libc::AF_UNIX as libc::sa_family_t,
            sun_path: [0; 108],
        };

        let path = Path::new(path);

        let mut len = path.as_os_str().len();
        if len > sockaddr.sun_path.len() {
            len = sockaddr.sun_path.len();
            // TODO: report warning
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                path.as_os_str().as_bytes().as_ptr(),
                sockaddr.sun_path.as_mut_ptr().cast(),
                len,
            )
        };

        let mut name = NgxStr::from(name);

        let mut pc = ngx_peer_connection_t {
            connection: std::ptr::null_mut(),
            sockaddr: ((&mut sockaddr) as *mut sockaddr_un).cast(),
            socklen: std::mem::size_of_val(&sockaddr) as u32,
            name: name.as_mut_ptr(),
            tries: 0,
            start_time: 0,
            get: Some(empty_get),
            free: Some(on_free),
            notify: None,
            data: std::ptr::null_mut(),
            set_session: None,
            save_session: None,
            local: std::ptr::null_mut(),
            type_: 0,
            rcvbuf: 0,
            log,
            _bitfield_align_1: Default::default(),
            _bitfield_1: Default::default(),
            __bindgen_padding_0: Default::default(),
        };

        let result = unsafe { ngx_event_connect_peer(&mut pc) };

        if result != NGX_OK as isize && result != NGX_AGAIN as isize {
            None
        } else {
            let conn = pc.connection;
            if conn.is_null() {
                None
            } else {
                Some(conn)
            }
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        match self {
            Self::WaitServerHandshake { conn, .. } => unsafe {
                if !(*conn).is_null() && (**conn).destroyed() == 0 {
                    (**conn).data = std::ptr::null_mut();
                    ngx_close_connection(*conn);
                }
            },
            Self::Connected { conn, .. } => unsafe {
                if !(*conn).is_null() && (**conn).destroyed() == 0 {
                    (**conn).data = std::ptr::null_mut();
                    ngx_close_connection(*conn);
                }
            },
            Self::Disconnected { event } => unsafe {
                if event.active() != 0 {
                    ngx_event_del_timer(event.as_mut());
                }
            },
        }
    }
}

unsafe fn conn_data(conn: *mut ngx_connection_t) -> *const Inner {
    (*conn).data.cast()
}

pub struct Disconnected;

impl UnixSocket {
    pub fn write(&self, buf: &[u8]) -> anyhow::Result<()> {
        self.0.write(buf)
    }
}

impl Inner {
    fn write(&self, buf: &[u8]) -> anyhow::Result<()> {
        match &mut *self.state.borrow_mut() {
            State::Connected {
                conn,
                ref mut buffers,
            } => {
                buffers.push(buf);
                unsafe {
                    buffers
                        .send(*conn)
                        .map_err(|_| anyhow::anyhow!("Disconnected"))
                }
            }
            State::WaitServerHandshake {
                conn,
                ref mut buffers,
            } => {
                buffers.push(buf);
                unsafe {
                    buffers
                        .send(*conn)
                        .map_err(|_| anyhow::anyhow!("Disconnected"))
                }
            }
            State::Disconnected { .. } => Err(anyhow::anyhow!("Disconnected")),
        }
    }

    // Unsafe - self should come from a Pinned address
    unsafe fn send(&self) {
        let state = &mut *self.state.borrow_mut();
        if let State::Connected { conn, buffers } = state {
            if let Err(Disconnected) = unsafe { buffers.send(*conn) } {
                *state = State::Disconnected {
                    event: self.create_and_schedule_reconnect(),
                };
            }
        }
    }

    // Unsafe - self should come from a Pined address
    unsafe fn create_and_schedule_reconnect(&self) -> Box<ngx_event_t> {
        let mut ev: Box<ngx_event_t> = Box::new(MaybeUninit::zeroed().assume_init());
        ev.handler = Some(on_reconnect_timeout);
        ev.log = (*ngx_cycle).log;
        ev.data = (self as *const Self as *mut Self).cast();

        ngx_event_add_timer(&mut *ev, TIMEOUT_MS);

        ev
    }
}

impl WriteBuffers {
    fn push(&mut self, data: &[u8]) {
        let mut data = data;
        if let Some(buf) = self.buffers.back_mut() {
            data = buf.push(data);
        }
        while !data.is_empty() {
            let mut buf = WriteBuffer::new();
            data = buf.push(data);
            self.buffers.push_back(buf);
        }
    }

    unsafe fn send(&mut self, conn: *mut ngx_connection_t) -> Result<(), Disconnected> {
        if let Some(send) = (*conn).send {
            while let Some(first) = self.buffers.front_mut() {
                if first.start == first.end {
                    break; // buffer empty
                }
                match first.send(conn, send) {
                    BufferSendResult::Ok => {}
                    BufferSendResult::EndOfStream => {
                        return Err(Disconnected);
                    }
                    BufferSendResult::Again => {
                        ngx_event_add_timer((*conn).write, TIMEOUT_MS);
                        if ngx_handle_write_event((*conn).write, 0) != NGX_OK as isize {
                            return Err(Disconnected);
                        }
                        return Ok(());
                    }
                    BufferSendResult::Error => return Err(Disconnected),
                }
                /*if first.start == first.end {
                    first.start = 0;
                    first.end = 0; // reuse the space in this buffer
                    break; // buffer empty
                }*/
                if first.start as usize == first.data.len() {
                    self.buffers.pop_front();
                }
            }
            if (*(*conn).write).active() != 0 {
                if let Some(del) = ngx_event_actions.del {
                    del((*conn).write, NGX_RS_WRITE_EVENT as isize, 0);
                }
            }
        }
        Ok(())
    }
}

enum BufferSendResult {
    Ok,
    EndOfStream,
    Again,
    Error,
}

impl WriteBuffer {
    fn new() -> Self {
        let data = vec![0; 4096];
        Self {
            data: data.into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    fn push<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        if (self.end as usize) < self.data.len() {
            let available = self.data.len() - self.end as usize;
            let to_copy = available.min(data.len());
            let next_end = self.end as usize + to_copy;
            self.data[self.end as usize..next_end].copy_from_slice(&data[..to_copy]);
            self.end = next_end as u32;
            &data[to_copy..]
        } else {
            data
        }
    }

    unsafe fn send(
        &mut self,
        conn: *mut ngx_connection_t,
        send_fn: unsafe extern "C" fn(*mut ngx_connection_t, *mut u8, usize) -> isize,
    ) -> BufferSendResult {
        let sendable = &self.data[self.start as usize..self.end as usize];
        if !sendable.is_empty() {
            let result = send_fn(conn, sendable.as_ptr().cast_mut(), sendable.len());
            if result > 0 {
                self.start += result as u32;
                BufferSendResult::Ok
            } else if result == 0 {
                BufferSendResult::EndOfStream
            } else if result == NGX_AGAIN as isize {
                BufferSendResult::Again
            } else {
                BufferSendResult::Error
            }
        } else {
            BufferSendResult::Ok
        }
    }
}

unsafe extern "C" fn empty_get(_pc: *mut ngx_peer_connection_t, _data: *mut c_void) -> isize {
    NGX_OK as isize
}

unsafe extern "C" fn on_free(_pc: *mut ngx_peer_connection_t, _data: *mut c_void, _state: usize) {}

unsafe extern "C" fn on_write(wev: *mut ngx_event_t) {
    let conn = &mut *((*wev).data as *mut ngx_connection_t);
    if conn.destroyed() != 0 {
        return;
    }

    if (*wev).timedout() != 0 {
        return;
    }

    if (*wev).timer_set() != 0 {
        ngx_event_del_timer(wev);
    }

    let conn_data = conn_data(conn);
    if !conn_data.is_null() {
        (*conn_data).send();
    }
}

unsafe extern "C" fn on_read(rev: *mut ngx_event_t) {
    let conn = &mut *((*rev).data as *mut ngx_connection_t);
    if conn.destroyed() != 0 {
        return;
    }

    if (*rev).timedout() != 0 {
        conn.set_timedout(1);
        return;
    }

    if (*rev).timer_set() != 0 {
        ngx_event_del_timer(rev);
    }

    let data = conn_data(conn);
    if !data.is_null() {
        if let Some(recv) = conn.recv {
            let mut buf = [0; 1024];
            loop {
                let result = recv(conn, buf.as_mut_ptr(), buf.len());
                if result > 0 {
                    let mut handshake_done = false;
                    let mut is_connected = false;
                    {
                        let state = &mut *(*data).state.borrow_mut();

                        match state {
                            State::WaitServerHandshake { conn, buffers } => {
                                match ((*data).check_handshake.borrow_mut())(
                                    &buf[..result as usize],
                                ) {
                                    Ok(_) => {
                                        let new_conn = *conn;
                                        *conn = std::ptr::null_mut();
                                        handshake_done = true;
                                        *state = State::Connected {
                                            conn: new_conn,
                                            buffers: std::mem::take(buffers),
                                        }
                                    }
                                    Err(_) => {
                                        *state = State::Disconnected {
                                            event: (*data).create_and_schedule_reconnect(),
                                        }
                                    }
                                }
                            }
                            State::Connected { .. } => {
                                is_connected = true;
                            }

                            State::Disconnected { .. } => {}
                        }
                    } // state not borrowed here any more
                    if handshake_done {
                        let back_data = ((*data).after_handshake.borrow_mut())();
                        if !back_data.is_empty() && (*data).write(&back_data).is_err() {
                            *(*data).state.borrow_mut() = State::Disconnected {
                                event: (*data).create_and_schedule_reconnect(),
                            };
                        }
                    }
                    if is_connected {
                        let back_data = ((*data).on_read.borrow_mut())(&buf[..result as usize]);

                        if !back_data.is_empty() && (*data).write(&back_data).is_err() {
                            *(*data).state.borrow_mut() = State::Disconnected {
                                event: (*data).create_and_schedule_reconnect(),
                            };
                        }
                    }
                } else if result == 0 {
                    // error, signal connection close
                    *(*data).state.borrow_mut() = State::Disconnected {
                        event: (*data).create_and_schedule_reconnect(),
                    };
                    break;
                } else if result == NGX_AGAIN as isize {
                    if ngx_handle_read_event(conn.read, 0) != NGX_OK as isize {
                        *(*data).state.borrow_mut() = State::Disconnected {
                            event: (*data).create_and_schedule_reconnect(),
                        };
                    }
                    break;
                } else {
                    // error, retry reconnect
                    *(*data).state.borrow_mut() = State::Disconnected {
                        event: (*data).create_and_schedule_reconnect(),
                    };
                    break;
                }
            }
        }
    }
}

unsafe extern "C" fn on_reconnect_timeout(ev: *mut ngx_event_t) {
    let data = (*ev).data as *const Inner;
    if !data.is_null() {
        let data = &*data;
        let mut state = data.state.borrow_mut();
        if let State::Disconnected { .. } = &*state {
            if let Some(conn) = State::try_connect(
                &data.path,
                &data.name,
                &*data.dummy_log as *const ngx_log_t as *mut ngx_log_t,
            ) {
                (*conn).data = (*ev).data;
                (*(*conn).write).handler = Some(on_write);
                (*(*conn).read).handler = Some(on_read);

                let mut buffers = WriteBuffers::default();
                buffers.push(&data.handshake_msg);
                *state = match unsafe { buffers.send(conn) } {
                    Ok(()) => State::WaitServerHandshake { conn, buffers },
                    Err(_) => unsafe {
                        let mut ev: Box<ngx_event_t> =
                            Box::new(MaybeUninit::zeroed().assume_init());
                        ev.handler = Some(on_reconnect_timeout);
                        ev.log = (*ngx_cycle).log;
                        if (*ev).timer_set() == 0
                            && ngx_quit == 0
                            && ngx_exiting == 0
                            && ngx_terminate == 0
                        {
                            ngx_event_add_timer(&mut *ev, TIMEOUT_MS);
                        }
                        State::Disconnected { event: ev }
                    },
                };
            } else if (*ev).timer_set() == 0
                && ngx_quit == 0
                && ngx_exiting == 0
                && ngx_terminate == 0
            {
                ngx_event_add_timer(ev, TIMEOUT_MS);
            }
        }
    }
}

unsafe extern "C" fn dummy_log_fn(_log: *mut ngx_log_t, _level: usize, _buf: *mut u8, _len: usize) {
}
