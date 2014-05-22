#![allow(dead_code)]

//! Implementation of a socks5 proxy
//!
//! http://www.ietf.org/rfc/rfc1928.txt

use std::io::net::addrinfo::get_host_addresses;
use std::io::net::ip::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::io::net::tcp::{TcpListener, TcpStream};
use std::io::{Listener, Acceptor, IoResult};
use std::io;
use std::str;

static VERSION: u8 = 5;

static METH_NO_AUTH: u8 = 0;
static METH_GSSAPI: u8 = 1;
static METH_USER_PASS: u8 = 2;

static CMD_CONNECT: u8 = 1;
static CMD_BIND: u8 = 2;
static CMD_UDP_ASSOCIATE: u8 = 3;

static ATYP_IPV4: u8 = 1;
static ATYP_IPV6: u8 = 4;
static ATYP_DOMAIN: u8 = 3;

fn main() {
    println!("listening on 0.0.0.0:8089");
    for l in TcpListener::bind("0.0.0.0", 8089).listen().incoming() {
        let l = l.unwrap();
        spawn(proc() {
            let mut l = l;
            let name = l.peer_name();
            println!("client: {} -- {}", name, handle(l));
        });
    }
}

fn handle(mut s: TcpStream) -> IoResult<()> {
    let vers = try!(s.read_byte());
    assert_eq!(vers, VERSION);
    let mut methods = Vec::new();
    for _ in range(0, try!(s.read_byte())) {
        methods.push(try!(s.read_byte()));
    }

    // Only support requests with no authentication for now
    if methods.contains(&METH_NO_AUTH) {
        try!(s.write([VERSION, METH_NO_AUTH]));
    } else {
        return s.write([VERSION, 0xff]);
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
            let name = try!(s.read_exact(nbytes as uint));
            let name = match str::from_utf8(name.as_slice()) {
                Some(n) => n,
                None => fail!("hostname not utf8"),
            };
            match try!(get_host_addresses(name)).as_slice().head() {
                Some(&addr) => addr,
                None => fail!("no ips for hostname: {}", name),
            }
        }
        n => fail!("invalid ATYP field: {}", n),
    };
    let port = try!(s.read_be_u16());

    match cmd {
        CMD_CONNECT => connect(s, ip, port),
        // Only the bind command is supported for now
        n => fail!("unsupported command: {}", n),
    }
}

fn connect(mut s: TcpStream, ip: IpAddr, port: u16) -> IoResult<()> {
    let mut remote = TcpStream::connect(ip.to_str().as_slice(), port);

    // Send the response of the result of the connection
    try!(s.write([5, if remote.is_ok() {0} else {5}, 0]));
    fn write_addr(s: &mut TcpStream, ip: IpAddr, port: u16) -> IoResult<()> {
        match ip {
            Ipv4Addr(a, b, c, d) => {
                try!(s.write([1, a, b, c, d]));
            }
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                try!(s.write([4]));
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
        s.write_be_u16(port)
    }
    match remote {
        Ok(ref mut r) => {
            let name = r.socket_name().unwrap();
            try!(write_addr(&mut s, name.ip, name.port));
        }
        Err(..) => {
            try!(write_addr(&mut s, ip, port));
        }
    }

    // Now that we've finished our handshake, get two tasks going to shuttle
    // data in both directions for this connection.
    let r = try!(remote);
    let s2 = s.clone();
    let r2 = r.clone();

    fn cp(mut reader: TcpStream, mut writer: TcpStream) -> IoResult<()> {
        let err = io::util::copy(&mut reader, &mut writer);
        // close other halves
        let _ = reader.close_write();
        let _ = writer.close_read();
        err
    }

    let (tx, rx) = channel();
    spawn(proc() { tx.send(cp(s2, r2)); });
    cp(r, s).and(rx.recv())
}
