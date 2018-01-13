extern crate futures;
extern crate synac;
extern crate tokio_core;

use futures::Future;
use std::cell::RefCell;
use std::net::ToSocketAddrs;
use synac::{Session, State};
use tokio_core::reactor::Core;

fn main() {
    // TODO: Error checking

    let mut core = Core::new().unwrap();
    let session = Session::new(
        &env!("ADDR").to_socket_addrs().unwrap().next().unwrap(),
        env!("HASH"),
        &core.handle()
    );
    let mut session = core.run(session).unwrap();

    session.login_with_token(true, env!("USERNAME"), env!("TOKEN")).unwrap(); // true specifies it's a bot account

    // First packet should be either LoginSuccess or an error

    let state = RefCell::new(State::new());

    core.run(session.read_loop(move |packet| {
        state.borrow_mut().update(&packet);

        // TODO: Use packet
        println!("{:?}", packet);
    }).map_err(|_| ())).unwrap();
}
