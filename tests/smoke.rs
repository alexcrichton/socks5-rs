extern crate conduit_static;
extern crate civet;
extern crate curl;

use std::net::TcpStream;
use std::process::{Command, Child};
use std::thread;
use std::time::Duration;

use civet::{Config, Server};
use curl::http::Handle;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {}", stringify!($e), e),
    })
}

fn main() {
    let mut cfg = Config::new();
    cfg.port(8888).threads(1);
    let _a = Server::start(cfg, conduit_static::Static::new("tests"));
    let proxy = Command::new("target/debug/socks5").spawn().unwrap();

    // Wait for server to come online
    while TcpStream::connect("127.0.0.1:9093").is_err() {
        thread::sleep(Duration::from_millis(50));
    }

    struct Bomb { c: Child }
    impl Drop for Bomb {
        fn drop(&mut self) { drop(self.c.kill()) }
    }
    let _b = Bomb { c: proxy };

    test("socks5://localhost:9093");
    test("socks4a://localhost:9093");
    test("socks4://localhost:9093");
}

fn test(proxy: &str) {
    println!("testing {}", proxy);
    let mut handle = Handle::new().proxy(proxy);
    let response = handle.get("http://127.0.0.1:8888/data").exec().unwrap();
    assert_eq!(response.get_code(), 200);
    assert_eq!(response.get_body(), b"test\n");
}
