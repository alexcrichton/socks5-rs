#![feature(io, core, std_misc)]
#![allow(dead_code)]

//! Implementation of a socks5 proxy
//!
//! http://www.ietf.org/rfc/rfc1928.txt
//! http://en.wikipedia.org/wiki/SOCKS

use std::old_io::net::tcp::{TcpListener, TcpStream};
use std::old_io::{Listener, Acceptor, IoResult};
use std::old_io;
use std::sync::mpsc::channel;
use std::thread::Thread;

fn main() {
    println!("listening on 0.0.0.0:8089");
    for l in TcpListener::bind(("0.0.0.0", 8089)).listen().incoming() {
        let l = l.unwrap();
        Thread::spawn(move|| {
            let mut l = l;
            let name = l.peer_name();
            println!("client: {:?} -- {:?}", name, handle(l));
        });
    }
}

fn handle(mut s: TcpStream) -> IoResult<()> {
    match try!(s.read_byte()) {
        v5::VERSION => match try!(v5::request(&mut s)) {
            v5::Request::Connect(addr) => {
                let remote = try!(v5::connect(&mut s, addr));
                proxy(s, remote)
            }
        },

        v4::VERSION => match try!(v4::request(&mut s)) {
            v4::Request::Connect(addr, _) => {
                let remote = try!(v4::connect(&mut s, addr));
                proxy(s, remote)
            }
        },

        _ => Err(other_err("unsupported version")),
    }
}

fn proxy(client: TcpStream, remote: TcpStream) -> IoResult<()> {
    let client2 = client.clone();
    let remote2 = remote.clone();

    fn cp(mut reader: TcpStream, mut writer: TcpStream) -> IoResult<()> {
        let err = old_io::util::copy(&mut reader, &mut writer);
        // close other halves
        let _ = reader.close_write();
        let _ = writer.close_read();
        err
    }

    let (tx, rx) = channel();
    Thread::spawn(move|| { tx.send(cp(client2, remote2)).unwrap(); });
    cp(remote, client).and(rx.recv().unwrap())
}

fn other_err(s: &'static str) -> old_io::IoError {
    old_io::IoError { kind: old_io::OtherIoError, desc: s, detail: None }
}

pub mod v5 {
    use std::old_io::net::addrinfo::get_host_addresses;
    use std::old_io::net::ip::{SocketAddr, Ipv4Addr, Ipv6Addr};
    use std::old_io::net::tcp::TcpStream;
    use std::old_io;
    use std::str;

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

    #[derive(Copy)]
    pub enum Request {
        Connect(SocketAddr)
    }

    /// Process a request from the client provided.
    ///
    /// It is assumed that the version number has already been read.
    pub fn request(s: &mut TcpStream) -> old_io::IoResult<Request> {
        let mut methods = Vec::new();
        for _ in range(0, try!(s.read_byte())) {
            methods.push(try!(s.read_byte()));
        }

        // Only support requests with no authentication for now
        if methods.contains(&METH_NO_AUTH) {
            try!(s.write_all(&[VERSION, METH_NO_AUTH]));
        } else {
            try!(s.write_all(&[VERSION, 0xff]));
            return Err(::other_err("no supported method given"))
        }

        assert_eq!(try!(s.read_byte()), VERSION);
        let cmd = try!(s.read_byte());
        let _rsv = try!(s.read_byte());

        // Decode the incoming IP/port
        let ip = match try!(s.read_byte()) {
            0x01 => Ipv4Addr(try!(s.read_byte()),
                             try!(s.read_byte()),
                             try!(s.read_byte()),
                             try!(s.read_byte())),

            0x04 => Ipv6Addr(try!(s.read_be_u16()),
                             try!(s.read_be_u16()),
                             try!(s.read_be_u16()),
                             try!(s.read_be_u16()),
                             try!(s.read_be_u16()),
                             try!(s.read_be_u16()),
                             try!(s.read_be_u16()),
                             try!(s.read_be_u16())),
            0x03 => {
                let nbytes = try!(s.read_byte());
                let name = try!(s.read_exact(nbytes as usize));
                let name = match str::from_utf8(name.as_slice()).ok() {
                    Some(n) => n,
                    None => return Err(::other_err("invalid hostname provided"))
                };
                match try!(get_host_addresses(name)).as_slice().first() {
                    Some(&addr) => addr,
                    None => return Err(::other_err("no valid ips for hostname"))
                }
            }
            _ => return Err(::other_err("invalid ATYP field")),
        };
        let port = try!(s.read_be_u16());

        match cmd {
            CMD_CONNECT => Ok(Request::Connect(SocketAddr { ip: ip, port: port })),
            // Only the connect command is supported for now
            _ => Err(::other_err("unsupported command"))
        }
    }

    /// Connect to the remote address for the client specified.
    ///
    /// If successful, returns the remote connection that was established.
    pub fn connect(s: &mut TcpStream, addr: SocketAddr) -> old_io::IoResult<TcpStream> {
        let mut remote = TcpStream::connect(addr);

        // Send the response of the result of the connection
        let code = match remote {
            Ok(..) => 0,
            Err(ref e) if e.kind == old_io::ConnectionRefused => 5,
            Err(ref e) if e.kind == old_io::ConnectionFailed => 4,
            Err(..) => 1,
        };
        try!(s.write_all(&[5, code, 0]));

        fn write_addr(s: &mut TcpStream, addr: SocketAddr) -> old_io::IoResult<()> {
            match addr.ip {
                Ipv4Addr(a, b, c, d) => {
                    try!(s.write_all(&[1, a, b, c, d]));
                }
                Ipv6Addr(a, b, c, d, e, f, g, h) => {
                    try!(s.write_all(&[4]));
                    try!(s.write_be_u16(a));
                    try!(s.write_be_u16(b));
                    try!(s.write_be_u16(c));
                    try!(s.write_be_u16(d));
                    try!(s.write_be_u16(e));
                    try!(s.write_be_u16(f));
                    try!(s.write_be_u16(g));
                    try!(s.write_be_u16(h));
                }
            }
            s.write_be_u16(addr.port)
        }
        match remote {
            Ok(ref mut r) => try!(write_addr(s, r.socket_name().unwrap())),
            Err(..) => try!(write_addr(s, addr)),
        }

        // Now that we've finished our handshake, get two tasks going to shuttle
        // data in both directions for this connection.
        remote
    }
}

pub mod v4 {
    use std::old_io::net::addrinfo::get_host_addresses;
    use std::old_io::net::ip::{SocketAddr, Ipv4Addr, Ipv6Addr};
    use std::old_io::net::tcp::TcpStream;
    use std::old_io::{self, ByRefReader};
    use std::str;

    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;

    pub enum Request {
        Connect(SocketAddr, Vec<u8>)
    }

    fn by_ref<'a, R: Reader>(r: &'a mut R) -> old_io::RefReader<'a, R> { r.by_ref() }

    /// Process a request from the client provided.
    ///
    /// It is assumed that the version number has already been read.
    pub fn request(s: &mut TcpStream) -> old_io::IoResult<Request> {
        let mut b = old_io::BufferedReader::new(by_ref(s));
        // assert_eq!(try!(s.read_byte()), VERSION);
        let cmd = try!(b.read_byte());
        let port = try!(b.read_be_u16());
        let ip = Ipv4Addr(try!(b.read_byte()),
                          try!(b.read_byte()),
                          try!(b.read_byte()),
                          try!(b.read_byte()));
        let mut id = try!(b.read_until(0));
        id.pop();

        let ip = match ip {
            Ipv4Addr(0, 0, 0, n) if n != 0 => {
                let mut name = try!(b.read_until(0));
                name.pop();
                let name = match str::from_utf8(name.as_slice()).ok() {
                    Some(s) => s,
                    None => return Err(::other_err("invalid domain name")),
                };
                match try!(get_host_addresses(name)).as_slice() {
                    [ip, ..] => ip,
                    [] => return Err(::other_err("no ips for domain name")),
                }
            }
            ip => ip,
        };

        match cmd {
            CMD_CONNECT => Ok(Request::Connect(SocketAddr { ip: ip, port: port }, id)),
            // Only the connect command is supported for now
            _ => Err(::other_err("unsupported command"))
        }
    }

    /// Connect to the remote address for the client specified.
    ///
    /// If successful, returns the remote connection that was established.
    pub fn connect(s: &mut TcpStream,
                   addr: SocketAddr) -> old_io::IoResult<TcpStream> {
        let remote = TcpStream::connect(addr);

        // Send the response of the result of the connection
        let code = if remote.is_ok() {0x5a} else {0x5b};
        try!(s.write_all(&[0, code]));
        try!(s.write_be_u16(addr.port));
        match addr.ip {
            Ipv4Addr(a, b, c, d) => try!(s.write_all(&[a, b, c, d])),
            Ipv6Addr(..) => panic!("no ipv6 in socks4"),
        }
        remote
    }
}
