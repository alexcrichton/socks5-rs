#![feature(lookup_host)]
#![allow(dead_code)]

//! Implementation of a socks5 proxy
//!
//! http://www.ietf.org/rfc/rfc1928.txt
//! http://en.wikipedia.org/wiki/SOCKS

extern crate mio;
extern crate bytes;

use std::collections::HashMap;
use std::io::prelude::*;
use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::net;
use std::str;

use bytes::{RingBuf, Buf, MutBuf};
use mio::prelude::*;
use mio::tcp::{TcpListener, TcpStream};
use mio::{Token, EventSet, PollOpt};

const SERVER: Token = Token(0);

// ::bind -- can't take a string

struct Server {
    server: TcpListener,
    next_token: usize,
    clients: HashMap<Token, Client>,
}

struct Client {
    stream: TcpStream,
    state: State,
    token: Token,
}

#[derive(Debug)]
enum State {
    UnknownVersion,

    // State transition through the V5 protocol
    V5ReadNumMethods,
    V5ReadMethods(u8, Vec<u8>),
    V5WriteVersion,
    V5WriteNoAuth,
    V5VersionAck,
    V5ReadCommand,
    V5ReadRSV,
    V5ReadATYP,
    V5ReadIpv4Addr(usize, [u8; 6]),
    V5ReadIpv6Addr(usize, [u8; 18]),
    V5ReadHostname(Option<usize>, Vec<u8>),
    V5Connect(SocketAddr),

    // State transition through the V4 protocol
    V4ReadCommand,
    V4ReadIpv4Addr(usize, [u8; 6]),
    V4ReadId(Vec<u8>, Ipv4Addr, u16),
    V4ReadHostname(Vec<u8>, u16),
    V4Connect(SocketAddrV4),

    WriteConnectHandshake(io::Result<TcpStream>, usize, Vec<u8>),
    Proxy(TcpStream, RingBuf, RingBuf),
}

type MyResult<T> = Result<T, MyError>;

enum MyError {
    IO(io::Error),
    KeepGoing,
    Done,
}

impl From<io::Error> for MyError {
    fn from(e: io::Error) -> MyError { MyError::IO(e) }
}
impl From<str::Utf8Error> for MyError {
    fn from(_: str::Utf8Error) -> MyError {
        ioerr(io::ErrorKind::Other, "invalid domain name")
    }
}

fn main() {
    println!("listening on 0.0.0.0:9093");
    let server = TcpListener::bind(&"0.0.0.0:9093".parse().unwrap()).unwrap();
    let mut events = EventLoop::new().unwrap();
    events.register(&server, SERVER, EventSet::all(), PollOpt::edge()).unwrap();
    events.run(&mut Server {
        server: server,
        next_token: 1,
        clients: HashMap::new(),
    }).unwrap();
}

fn ioerr(kind: io::ErrorKind, msg: &str) -> MyError {
    MyError::IO(io::Error::new(kind, msg))
}

impl mio::Handler for Server {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token,
             events: EventSet) {
        if token == SERVER {
            if events.is_readable() {
                self.accept_client(event_loop).unwrap();
            } else {
                panic!("wut2");
            }
            return
        }

        {
            let client = self.clients.get_mut(&token).unwrap();
            match client.handle(event_loop) {
                Ok(()) |
                Err(MyError::KeepGoing) => return,
                Err(MyError::Done) => {}
                Err(MyError::IO(io)) => {
                    println!("error on {:?}: {}", client.stream.local_addr(), io);
                }
            }
        }
        let client = self.clients.remove(&token).unwrap();
        event_loop.deregister(&client.stream).unwrap();
        if let State::Proxy(ref stream, _, _) = client.state {
            event_loop.deregister(stream).unwrap();
        }
    }
}

impl Server {
    fn accept_client(&mut self, event_loop: &mut EventLoop<Server>)
                     -> io::Result<()> {
        if let Some((conn, _)) = try!(self.server.accept()) {
            let new_token = Token(self.next_token);
            self.next_token += 1;
            try!(event_loop.register(&conn, new_token,
                                     EventSet::readable() |
                                        EventSet::writable(),
                                     PollOpt::edge()));
            self.clients.insert(new_token, Client {
                stream: conn,
                state: State::UnknownVersion,
                token: new_token,
            });
        }
        Ok(())
    }
}

impl Client {
    fn handle(&mut self, event_loop: &mut EventLoop<Server>) -> MyResult<()> {
        loop {
            try!(self.transition(event_loop));
        }
    }

    fn transition(&mut self, event_loop: &mut EventLoop<Server>) -> MyResult<()> {
        let next_state = match self.state {
            State::UnknownVersion => {
                match try!(read_byte(&mut self.stream)) {
                    v5::VERSION => State::V5ReadNumMethods,
                    v4::VERSION => State::V4ReadCommand,
                    _ => {
                        let desc = "unknown version sent for connection";
                        return Err(ioerr(io::ErrorKind::Other, desc))
                    }
                }
            }
            State::V5ReadNumMethods => {
                let amt = try!(read_byte(&mut self.stream));
                State::V5ReadMethods(amt, vec![0; amt as usize])
            }
            State::V5ReadMethods(ref mut n, ref mut methods) => {
                let start = methods.len() - *n as usize;
                let read = try!(read_nonzero(&mut self.stream,
                                             &mut methods[start..]));
                *n -= read as u8;
                if methods.contains(&v5::METH_NO_AUTH) {
                    State::V5WriteVersion
                } else {
                    return Err(ioerr(io::ErrorKind::Other,
                                     "no supported method given"))
                }
            }
            State::V5WriteVersion => {
                try!(write_byte(&mut self.stream, v5::VERSION));
                State::V5WriteNoAuth
            }
            State::V5WriteNoAuth => {
                try!(write_byte(&mut self.stream, v5::METH_NO_AUTH));
                State::V5VersionAck
            }
            State::V5VersionAck => {
                if try!(read_byte(&mut self.stream)) != v5::VERSION {
                    return Err(ioerr(io::ErrorKind::Other,
                                     "didn't confirm with v5 version"))
                }
                State::V5ReadCommand
            }
            State::V5ReadCommand => {
                let cmd = try!(read_byte(&mut self.stream));
                if cmd != v5::CMD_CONNECT {
                    return Err(ioerr(io::ErrorKind::Other,
                                     "unsupported command"))
                }
                State::V5ReadRSV
            }
            State::V5ReadRSV => {
                try!(read_byte(&mut self.stream));
                State::V5ReadATYP
            }
            State::V5ReadATYP => {
                match try!(read_byte(&mut self.stream)) {
                    v5::ATYP_IPV4 => State::V5ReadIpv4Addr(0, [0; 6]),
                    v5::ATYP_IPV6 => State::V5ReadIpv6Addr(0, [0; 18]),
                    v5::ATYP_DOMAIN => State::V5ReadHostname(None, Vec::new()),
                    _ => return Err(ioerr(io::ErrorKind::Other,
                                          "invalid ATYP field")),
                }
            }
            State::V5ReadIpv4Addr(ref mut amt, ref mut bytes) => {
                while *amt < bytes.len() {
                    *amt += try!(read_nonzero(&mut self.stream,
                                              &mut bytes[*amt..]));
                }
                let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                let port = ((bytes[4] as u16) << 8) | (bytes[5] as u16);
                let addr = SocketAddrV4::new(addr, port);
                State::V5Connect(SocketAddr::V4(addr))
            }
            State::V5ReadIpv6Addr(..) => {
                panic!("wut");
            }
            State::V5ReadHostname(..) => {
                panic!("wut");
            }
            State::V5Connect(ref addr) => {
                let stream = TcpStream::connect(addr);
                let mut resp = Vec::new();
                resp.push(5);
                resp.push(match stream {
                    Ok(..) => 0,
                    Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                    Err(..) => 1,
                });
                resp.push(0);
                let addr = match stream.as_ref().map(|r| r.local_addr()) {
                    Ok(Ok(addr)) => addr,
                    Ok(Err(..)) |
                    Err(..) => *addr,
                };
                match addr {
                    SocketAddr::V4(ref a) => {
                        resp.push(1);
                        resp.extend(a.ip().octets().iter().cloned());
                    }
                    SocketAddr::V6(ref a) => {
                        resp.push(4);
                        for &segment in a.ip().segments().iter() {
                            resp.push((segment >> 8) as u8);
                            resp.push(segment as u8);
                        }
                    }
                }
                resp.push((addr.port() >> 8) as u8);
                resp.push(addr.port() as u8);
                State::WriteConnectHandshake(stream, 0, resp)
            }

            State::V4ReadCommand => {
                let cmd = try!(read_byte(&mut self.stream));
                if cmd != v4::CMD_CONNECT {
                    return Err(ioerr(io::ErrorKind::Other,
                                     "unsupported command"))
                }
                State::V4ReadIpv4Addr(0, [0; 6])
            }
            State::V4ReadIpv4Addr(ref mut len, ref mut bytes) => {
                while *len < bytes.len() {
                    *len += try!(read_nonzero(&mut self.stream,
                                              &mut bytes[*len..]));
                }
                let port = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
                let ip = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
                State::V4ReadId(Vec::new(), ip, port)
            }
            State::V4ReadId(ref mut v, ref ip, port) => {
                loop {
                    match try!(read_byte(&mut self.stream)) {
                        0 => break,
                        n => v.push(n),
                    }
                }
                let octets = ip.octets();
                if octets[0] == 0 && octets[1] == 0 && octets[2] == 0 &&
                   octets[3] != 0 {
                    State::V4ReadHostname(Vec::new(), port)
                } else {
                    State::V4Connect(SocketAddrV4::new(*ip, port))
                }
            }
            State::V4ReadHostname(ref mut bytes, port) => {
                loop {
                    match try!(read_byte(&mut self.stream)) {
                        0 => break,
                        n => bytes.push(n),
                    }
                }
                let name = try!(str::from_utf8(bytes));
                let addr = try!(net::lookup_host(name)).filter_map(|addr| {
                    match addr {
                        Ok(SocketAddr::V4(ref a)) => {
                            Some(SocketAddrV4::new(*a.ip(), port))
                        }
                        Ok(SocketAddr::V6(..)) |
                        Err(..) => None
                    }
                }).next();
                let addr = try!(addr.ok_or_else(|| {
                    ioerr(io::ErrorKind::Other,
                          "no v4 addresses for domain name")
                }));
                State::V4Connect(addr)
            }
            State::V4Connect(ref addr) => {
                let stream = TcpStream::connect(&SocketAddr::V4(*addr));
                let mut resp = Vec::new();
                resp.push(0);
                resp.push(if stream.is_ok() {0x5a} else {0x5b});
                resp.push((addr.port() >> 8) as u8);
                resp.push(addr.port() as u8);
                resp.extend(addr.ip().octets().iter());
                State::WriteConnectHandshake(stream, 0, resp)
            }

            State::WriteConnectHandshake(ref mut stream, ref mut nbytes,
                                         ref bytes) => {
                while *nbytes < bytes.len() {
                    *nbytes += try!(write_nonzero(&mut self.stream,
                                                  &bytes[*nbytes..]));
                }
                let err = io::Error::new(io::ErrorKind::Other, "");
                let stream = try!(mem::replace(stream, Err(err)));
                try!(event_loop.register(&stream, self.token,
                                         EventSet::readable() |
                                            EventSet::writable(),
                                         PollOpt::edge()));
                let incoming = RingBuf::new(32 * 1024);
                let outgoing = RingBuf::new(32 * 1024);
                State::Proxy(stream, incoming, outgoing)
            }
            State::Proxy(ref mut stream, ref mut a, ref mut b) => {
                let mut eof = 0;
                while Buf::bytes(a).len() > 0 {
                    match try!(stream.try_write(Buf::bytes(a))) {
                        Some(n) => Buf::advance(a, n),
                        None => break,
                    }
                }
                unsafe {
                    while a.mut_bytes().len() > 0 {
                        match try!(self.stream.try_read(a.mut_bytes())) {
                            Some(0) => { eof += 1; break }
                            Some(n) => MutBuf::advance(a, n),
                            None => break,
                        }
                    }
                }
                while Buf::bytes(b).len() > 0 {
                    match try!(self.stream.try_write(Buf::bytes(b))) {
                        Some(n) => Buf::advance(b, n),
                        None => break,
                    }
                }
                unsafe {
                    while b.mut_bytes().len() > 0 {
                        match try!(stream.try_read(b.mut_bytes())) {
                            Some(0) => { eof += 1; break }
                            Some(n) => MutBuf::advance(b, n),
                            None => break,
                        }
                    }
                }
                return if eof == 2 {
                    Err(MyError::Done)
                } else {
                    Ok(())
                }
            }
        };
        self.state = next_state;
        Ok(())
    }
}

fn read_byte(stream: &mut Read) -> MyResult<u8> {
    let mut vers = [0];
    try!(read_nonzero(stream, &mut vers));
    Ok(vers[0])
}

fn read_nonzero(mut stream: &mut Read, bytes: &mut [u8]) -> MyResult<usize> {
    match try!(stream.try_read(bytes)) {
        Some(0) => Err(ioerr(io::ErrorKind::Other, "early eof")),
        Some(n) => Ok(n),
        None => Err(MyError::KeepGoing),
    }
}

fn write_byte(stream: &mut Write, byte: u8) -> MyResult<()> {
    try!(write_nonzero(stream, &[byte]));
    Ok(())
}

fn write_nonzero(mut stream: &mut Write, bytes: &[u8]) -> MyResult<usize> {
    match try!(stream.try_write(bytes)) {
        Some(0) => Err(ioerr(io::ErrorKind::Other, "early eof")),
        Some(n) => Ok(n),
        None => Err(MyError::KeepGoing),
    }
}


pub mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

pub mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}
