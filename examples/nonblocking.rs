extern crate synac;

use std::thread;
use std::time::Duration;
use synac::{Listener, Session, State};

fn main() {
    // TODO: Error checking
    let mut session = Session::new(env!("ADDR"), env!("HASH")).unwrap();
    session.login_with_token(true, env!("USERNAME"), env!("TOKEN")).unwrap(); // true specifies it's a bot account

    // First packet should be either LoginSuccess or an error
    let result = session.read().unwrap();
    // TODO: Use result

    session.set_nonblocking(true).unwrap();

    let mut state = State::new();
    let mut listener = Listener::new();

    loop {
        let packet = listener.try_read(session.inner_stream()).unwrap(); // <- non blocking
        if let Some(packet) = packet {
            state.update(&packet);

            // TODO: Use packet
        }

        thread::sleep(Duration::from_millis(100));
    }
}
