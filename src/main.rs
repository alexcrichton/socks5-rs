#![feature(io, lookup_host)]
#![allow(dead_code)]

//! Implementation of a socks5 proxy
//!
//! http://www.ietf.org/rfc/rfc1928.txt
//! http://en.wikipedia.org/wiki/SOCKS

extern crate byteorder;

use std::io;
use std::net::{TcpStream, TcpListener, Shutdown};
use std::thread;

use byteorder::ReadBytesExt;

fn main() {
    println!("listening on 0.0.0.0:9093");
    for l in TcpListener::bind("0.0.0.0:9093").unwrap().incoming() {
        let l = match l {
            Ok(t) => t,
            Err(..) => break
        };
        thread::spawn(move|| {
            let name = l.peer_addr();
            println!("client: {:?} -- {}", name, match handle(l) {
                Ok(()) => "ok".to_string(),
                Err(e) => e.to_string(),
            });
        });
    }
}

fn handle(mut s: TcpStream) -> io::Result<()> {
    match try!(s.read_u8()) {
        v5::VERSION => match try!(v5::request(&mut s)) {
            v5::Request::Connect(ref addr) => {
                let remote = try!(v5::connect(&mut s, addr));
                proxy(s, remote)
            }
        },

        v4::VERSION => match try!(v4::request(&mut s)) {
            v4::Request::Connect(ref addr, _) => {
                let remote = try!(v4::connect(&mut s, addr));
                proxy(s, remote)
            }
        },

        _ => Err(other_err("unsupported version")),
    }
}

fn proxy(client: TcpStream, remote: TcpStream) -> io::Result<()> {

    fn cp(mut reader: &TcpStream, mut writer: &TcpStream) -> io::Result<()> {
        let err = io::copy(&mut reader, &mut writer);
        // close other halves
        let _ = reader.shutdown(Shutdown::Write);
        let _ = writer.shutdown(Shutdown::Read);
        err.map(|_| ())
    }

    let child = thread::scoped(|| cp(&client, &remote));
    cp(&remote, &client).and(child.join())
}

fn other_err(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, s, None)
}

pub mod v5 {
    use std::io::prelude::*;
    use std::io;
    use std::net::{self, SocketAddr, TcpStream, Ipv4Addr, Ipv6Addr};
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::str;
    use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

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
    pub fn request(s: &mut TcpStream) -> io::Result<Request> {
        let mut methods = Vec::new();
        for _ in 0..try!(s.read_u8()) {
            methods.push(try!(s.read_u8()));
        }

        // Only support requests with no authentication for now
        if methods.contains(&METH_NO_AUTH) {
            try!(s.write_all(&[VERSION, METH_NO_AUTH]));
        } else {
            try!(s.write_all(&[VERSION, 0xff]));
            return Err(::other_err("no supported method given"))
        }

        assert_eq!(try!(s.read_u8()), VERSION);
        let cmd = try!(s.read_u8());
        let _rsv = try!(s.read_u8());

        // Decode the incoming IP/port
        let addr = match try!(s.read_u8()) {
            0x01 => {
                let ip = Ipv4Addr::new(try!(s.read_u8()),
                                       try!(s.read_u8()),
                                       try!(s.read_u8()),
                                       try!(s.read_u8()));
                let port = try!(s.read_u16::<BigEndian>());
                SocketAddr::V4(SocketAddrV4::new(ip, port))
            }
            0x04 => {
                let ip = Ipv6Addr::new(try!(s.read_u16::<BigEndian>()),
                                       try!(s.read_u16::<BigEndian>()),
                                       try!(s.read_u16::<BigEndian>()),
                                       try!(s.read_u16::<BigEndian>()),
                                       try!(s.read_u16::<BigEndian>()),
                                       try!(s.read_u16::<BigEndian>()),
                                       try!(s.read_u16::<BigEndian>()),
                                       try!(s.read_u16::<BigEndian>()));
                let port = try!(s.read_u16::<BigEndian>());
                SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
            }
            0x03 => {
                let nbytes = try!(s.read_u8());
                let mut name = Vec::new();
                try!(s.take(nbytes as u64).read_to_end(&mut name));
                let name = match str::from_utf8(&name).ok() {
                    Some(n) => n,
                    None => return Err(::other_err("invalid hostname provided"))
                };
                match try!(net::lookup_host(name)).next() {
                    Some(addr) => try!(addr),
                    None => return Err(::other_err("no valid ips for hostname"))
                }
            }
            _ => return Err(::other_err("invalid ATYP field")),
        };

        match cmd {
            CMD_CONNECT => Ok(Request::Connect(addr)),
            // Only the connect command is supported for now
            _ => Err(::other_err("unsupported command"))
        }
    }

    /// Connect to the remote address for the client specified.
    ///
    /// If successful, returns the remote connection that was established.
    pub fn connect(s: &mut TcpStream, addr: &SocketAddr) -> io::Result<TcpStream> {
        let mut remote = TcpStream::connect(addr);

        // Send the response of the result of the connection
        let code = match remote {
            Ok(..) => 0,
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
            // Err(ref e) if e.kind() == io::ErrorKind::ConnectionFailed => 4,
            Err(..) => 1,
        };
        try!(s.write_all(&[5, code, 0]));

        fn write_addr(s: &mut TcpStream, addr: &SocketAddr) -> io::Result<()> {
            match *addr {
                SocketAddr::V4(ref a) => {
                    try!(s.write_all(&[1]));
                    try!(s.write_all(&a.ip().octets()));
                }
                SocketAddr::V6(ref a) => {
                    try!(s.write_all(&[4]));
                    for segment in a.ip().segments().iter() {
                        try!(s.write_u16::<BigEndian>(*segment));
                    }
                }
            }
            try!(s.write_u16::<BigEndian>(addr.port()));
            Ok(())
        }
        match remote {
            Ok(ref mut r) => try!(write_addr(s, &r.local_addr().unwrap())),
            Err(..) => try!(write_addr(s, addr)),
        }

        // Now that we've finished our handshake, get two tasks going to shuttle
        // data in both directions for this connection.
        remote
    }
}

pub mod v4 {
    use std::io::prelude::*;
    use std::io::{self, BufReader};
    use std::net::{self, TcpStream, SocketAddr, Ipv4Addr, SocketAddrV4};
    use std::net::SocketAddrV6;
    use std::str;
    use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;

    pub enum Request {
        Connect(SocketAddr, Vec<u8>)
    }

    /// Process a request from the client provided.
    ///
    /// It is assumed that the version number has already been read.
    pub fn request(s: &mut TcpStream) -> io::Result<Request> {
        let mut b = BufReader::new(s);
        let cmd = try!(b.read_u8());
        let port = try!(b.read_u16::<BigEndian>());
        let ip = Ipv4Addr::new(try!(b.read_u8()),
                               try!(b.read_u8()),
                               try!(b.read_u8()),
                               try!(b.read_u8()));
        let mut id = Vec::new();
        try!(b.read_until(0, &mut id));
        id.pop();

        let octets = ip.octets();
        let addr = if octets[0] == 0 && octets[1] == 0 && octets[2] == 0 &&
                      octets[3] != 0 {
            let mut name = Vec::new();
            try!(b.read_until(0, &mut name));
            name.pop();
            let name = match str::from_utf8(&name).ok() {
                Some(s) => s,
                None => return Err(::other_err("invalid domain name")),
            };
            let addr = match try!(net::lookup_host(name)).next() {
                Some(addr) => try!(addr),
                None => return Err(::other_err("no ips for domain name")),
            };
            match addr {
                SocketAddr::V4(ref a) => {
                    SocketAddr::V4(SocketAddrV4::new(*a.ip(), port))
                }
                SocketAddr::V6(ref a) => {
                    SocketAddr::V6(SocketAddrV6::new(*a.ip(), port, 0, 0))
                }
            }
        } else {
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        };

        match cmd {
            CMD_CONNECT => Ok(Request::Connect(addr, id)),
            // Only the connect command is supported for now
            _ => Err(::other_err("unsupported command"))
        }
    }

    /// Connect to the remote address for the client specified.
    ///
    /// If successful, returns the remote connection that was established.
    pub fn connect(s: &mut TcpStream, addr: &SocketAddr)
                   -> io::Result<TcpStream> {
        let remote = TcpStream::connect(addr);

        // Send the response of the result of the connection
        let code = if remote.is_ok() {0x5a} else {0x5b};
        try!(s.write_all(&[0, code]));
        match *addr {
            SocketAddr::V4(ref a) => {
                try!(s.write_u16::<BigEndian>(a.port()));
                try!(s.write_all(&a.ip().octets()));
            }
            SocketAddr::V6(..) => panic!("no ipv6 in socks4"),
        }
        remote
    }
}
