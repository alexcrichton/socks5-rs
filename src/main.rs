#![feature(lookup_host)]
#![allow(dead_code)]

//! Implementation of a socks5 proxy
//!
//! http://www.ietf.org/rfc/rfc1928.txt
//! http://en.wikipedia.org/wiki/SOCKS

extern crate mio;

use std::collections::HashMap;
use std::io::prelude::*;
use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

use mio::buf::RingBuf;
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
    V5WriteConnectHandshake(io::Result<TcpStream>, usize, Vec<u8>),
    Proxy(TcpStream, RingBuf, RingBuf),
}

type MyResult<T> = Result<T, MyError>;

enum MyError {
    IO(io::Error),
    KeepGoing,
}

impl From<io::Error> for MyError {
    fn from(e: io::Error) -> MyError { MyError::IO(e) }
}

fn main() {
    println!("listening on 0.0.0.0:9093");
    let server = TcpListener::bind(&"0.0.0.0:9093".parse().unwrap()).unwrap();
    let mut events = EventLoop::new().unwrap();
    events.register(&server, SERVER).unwrap();
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
        println!("{:?}: {:?}", token, events);
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
                Err(MyError::IO(io)) => {
                    println!("error on {:?}: {}", client.stream.local_addr(), io);
                }
            }
        }
        let client = self.clients.remove(&token).unwrap();
        event_loop.deregister(&client.stream).unwrap();
    }
}

impl Server {
    fn accept_client(&mut self, event_loop: &mut EventLoop<Server>)
                     -> io::Result<()> {
        if let Some(conn) = try!(self.server.accept()) {
            let new_token = Token(self.next_token);
            self.next_token += 1;
            try!(event_loop.register_opt(&conn, new_token,
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
                    // v4::VERSION => { self.version = Version::V4; Ok(()) }
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
                    0x01 => State::V5ReadIpv4Addr(0, [0; 6]),
                    0x04 => State::V5ReadIpv6Addr(0, [0; 18]),
                    0x03 => State::V5ReadHostname(None, Vec::new()),
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
                State::V5WriteConnectHandshake(stream, 0, resp)
            }
            State::V5WriteConnectHandshake(ref mut stream, ref mut nbytes,
                                           ref bytes) => {
                while *nbytes < bytes.len() {
                    *nbytes += try!(write_nonzero(&mut self.stream,
                                                  &bytes[*nbytes..]));
                }
                let err = io::Error::new(io::ErrorKind::Other, "");
                let stream = try!(mem::replace(stream, Err(err)));
                try!(event_loop.register_opt(&stream, self.token,
                                             EventSet::readable() |
                                                EventSet::writable(),
                                             PollOpt::edge()));
                let incoming = RingBuf::new(32 * 1024);
                let outgoing = RingBuf::new(32 * 1024);
                State::Proxy(stream, incoming, outgoing)
            }
            State::Proxy(ref mut stream, ref mut incoming, ref mut outgoing) => {
                panic!("wut");
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

//
// fn handle(mut s: TcpStream) -> io::Result<()> {
//     match try!(s.read_u8()) {
//         v5::VERSION => match try!(v5::request(&mut s)) {
//             v5::Request::Connect(ref addr) => {
//                 let remote = try!(v5::connect(&mut s, addr));
//                 proxy(s, remote)
//             }
//         },
//
//         v4::VERSION => match try!(v4::request(&mut s)) {
//             v4::Request::Connect(ref addr, _) => {
//                 let remote = try!(v4::connect(&mut s, addr));
//                 proxy(s, remote)
//             }
//         },
//
//         _ => Err(other_err("unsupported version")),
//     }
// }

// fn proxy(client: TcpStream, remote: TcpStream) -> io::Result<()> {
//
//     fn cp(mut reader: &TcpStream, mut writer: &TcpStream) -> io::Result<()> {
//         let err = io::copy(&mut reader, &mut writer);
//         // close other halves
//         let _ = reader.shutdown(Shutdown::Write);
//         let _ = writer.shutdown(Shutdown::Read);
//         err.map(|_| ())
//     }
//
//     let pair1 = Arc::new((client, remote));
//     let pair2 = pair1.clone();
//
//     let child = thread::spawn(move || cp(&pair2.1, &pair2.0));
//     cp(&pair1.0, &pair1.1).and(child.join().unwrap())
// }

pub mod v5 {
    // use std::io::prelude::*;
    // use std::io;
    // use std::net::{self, SocketAddr, TcpStream, Ipv4Addr, Ipv6Addr};
    // use std::net::{SocketAddrV4, SocketAddrV6};
    // use std::str;
    // use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

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

    // #[derive(Copy, Clone)]
    // pub enum Request {
    //     Connect(SocketAddr)
    // }
    //
    // /// Process a request from the client provided.
    // ///
    // /// It is assumed that the version number has already been read.
    // pub fn request(s: &mut TcpStream) -> io::Result<Request> {
    //     let mut methods = Vec::new();
    //     for _ in 0..try!(s.read_u8()) {
    //         methods.push(try!(s.read_u8()));
    //     }
    //
    //     // Only support requests with no authentication for now
    //     if methods.contains(&METH_NO_AUTH) {
    //         try!(s.write_all(&[VERSION, METH_NO_AUTH]));
    //     } else {
    //         try!(s.write_all(&[VERSION, 0xff]));
    //         return Err(::other_err("no supported method given"))
    //     }
    //
    //     assert_eq!(try!(s.read_u8()), VERSION);
    //     let cmd = try!(s.read_u8());
    //     let _rsv = try!(s.read_u8());
    //
    //     // Decode the incoming IP/port
    //     let addr = match try!(s.read_u8()) {
    //         0x01 => {
    //             let ip = Ipv4Addr::new(try!(s.read_u8()),
    //                                    try!(s.read_u8()),
    //                                    try!(s.read_u8()),
    //                                    try!(s.read_u8()));
    //             let port = try!(s.read_u16::<BigEndian>());
    //             SocketAddr::V4(SocketAddrV4::new(ip, port))
    //         }
    //         0x04 => {
    //             let ip = Ipv6Addr::new(try!(s.read_u16::<BigEndian>()),
    //                                    try!(s.read_u16::<BigEndian>()),
    //                                    try!(s.read_u16::<BigEndian>()),
    //                                    try!(s.read_u16::<BigEndian>()),
    //                                    try!(s.read_u16::<BigEndian>()),
    //                                    try!(s.read_u16::<BigEndian>()),
    //                                    try!(s.read_u16::<BigEndian>()),
    //                                    try!(s.read_u16::<BigEndian>()));
    //             let port = try!(s.read_u16::<BigEndian>());
    //             SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
    //         }
    //         0x03 => {
    //             let nbytes = try!(s.read_u8());
    //             let mut name = Vec::new();
    //             try!(s.take(nbytes as u64).read_to_end(&mut name));
    //             let name = match str::from_utf8(&name).ok() {
    //                 Some(n) => n,
    //                 None => return Err(::other_err("invalid hostname provided"))
    //             };
    //             match try!(net::lookup_host(name)).next() {
    //                 Some(addr) => try!(addr),
    //                 None => return Err(::other_err("no valid ips for hostname"))
    //             }
    //         }
    //         _ => return Err(::other_err("invalid ATYP field")),
    //     };
    //
    //     match cmd {
    //         CMD_CONNECT => Ok(Request::Connect(addr)),
    //         // Only the connect command is supported for now
    //         _ => Err(::other_err("unsupported command"))
    //     }
    // }
    //
    // /// Connect to the remote address for the client specified.
    // ///
    // /// If successful, returns the remote connection that was established.
    // pub fn connect(s: &mut TcpStream, addr: &SocketAddr) -> io::Result<TcpStream> {
    //     let mut remote = TcpStream::connect(addr);
    //
    //     // Send the response of the result of the connection
    //     let code = match remote {
    //         Ok(..) => 0,
    //         Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
    //         // Err(ref e) if e.kind() == io::ErrorKind::ConnectionFailed => 4,
    //         Err(..) => 1,
    //     };
    //     try!(s.write_all(&[5, code, 0]));
    //
    //     fn write_addr(s: &mut TcpStream, addr: &SocketAddr) -> io::Result<()> {
    //         match *addr {
    //             SocketAddr::V4(ref a) => {
    //                 try!(s.write_all(&[1]));
    //                 try!(s.write_all(&a.ip().octets()));
    //             }
    //             SocketAddr::V6(ref a) => {
    //                 try!(s.write_all(&[4]));
    //                 for segment in a.ip().segments().iter() {
    //                     try!(s.write_u16::<BigEndian>(*segment));
    //                 }
    //             }
    //         }
    //         try!(s.write_u16::<BigEndian>(addr.port()));
    //         Ok(())
    //     }
    //     match remote {
    //         Ok(ref mut r) => try!(write_addr(s, &r.local_addr().unwrap())),
    //         Err(..) => try!(write_addr(s, addr)),
    //     }
    //
    //     // Now that we've finished our handshake, get two tasks going to shuttle
    //     // data in both directions for this connection.
    //     remote
    // }
}

pub mod v4 {
    // use std::io::prelude::*;
    // use std::io::{self, BufReader};
    // use std::net::{self, TcpStream, SocketAddr, Ipv4Addr, SocketAddrV4};
    // use std::net::SocketAddrV6;
    // use std::str;
    // use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;

    // pub enum Request {
    //     Connect(SocketAddr, Vec<u8>)
    // }
    //
    // /// Process a request from the client provided.
    // ///
    // /// It is assumed that the version number has already been read.
    // pub fn request(s: &mut TcpStream) -> io::Result<Request> {
    //     let mut b = BufReader::new(s);
    //     let cmd = try!(b.read_u8());
    //     let port = try!(b.read_u16::<BigEndian>());
    //     let ip = Ipv4Addr::new(try!(b.read_u8()),
    //                            try!(b.read_u8()),
    //                            try!(b.read_u8()),
    //                            try!(b.read_u8()));
    //     let mut id = Vec::new();
    //     try!(b.read_until(0, &mut id));
    //     id.pop();
    //
    //     let octets = ip.octets();
    //     let addr = if octets[0] == 0 && octets[1] == 0 && octets[2] == 0 &&
    //                   octets[3] != 0 {
    //         let mut name = Vec::new();
    //         try!(b.read_until(0, &mut name));
    //         name.pop();
    //         let name = match str::from_utf8(&name).ok() {
    //             Some(s) => s,
    //             None => return Err(::other_err("invalid domain name")),
    //         };
    //         let addr = match try!(net::lookup_host(name)).next() {
    //             Some(addr) => try!(addr),
    //             None => return Err(::other_err("no ips for domain name")),
    //         };
    //         match addr {
    //             SocketAddr::V4(ref a) => {
    //                 SocketAddr::V4(SocketAddrV4::new(*a.ip(), port))
    //             }
    //             SocketAddr::V6(ref a) => {
    //                 SocketAddr::V6(SocketAddrV6::new(*a.ip(), port, 0, 0))
    //             }
    //         }
    //     } else {
    //         SocketAddr::V4(SocketAddrV4::new(ip, port))
    //     };
    //
    //     match cmd {
    //         CMD_CONNECT => Ok(Request::Connect(addr, id)),
    //         // Only the connect command is supported for now
    //         _ => Err(::other_err("unsupported command"))
    //     }
    // }
    //
    // /// Connect to the remote address for the client specified.
    // ///
    // /// If successful, returns the remote connection that was established.
    // pub fn connect(s: &mut TcpStream, addr: &SocketAddr)
    //                -> io::Result<TcpStream> {
    //     let remote = TcpStream::connect(addr);
    //
    //     // Send the response of the result of the connection
    //     let code = if remote.is_ok() {0x5a} else {0x5b};
    //     try!(s.write_all(&[0, code]));
    //     match *addr {
    //         SocketAddr::V4(ref a) => {
    //             try!(s.write_u16::<BigEndian>(a.port()));
    //             try!(s.write_all(&a.ip().octets()));
    //         }
    //         SocketAddr::V6(..) => panic!("no ipv6 in socks4"),
    //     }
    //     remote
    // }
}
