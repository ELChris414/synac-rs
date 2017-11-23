# synac-rs [![Crates.io](https://img.shields.io/crates/v/synac.svg?style=flat-square)]()

A client side library for [synac](https://github.com/jD91mZM2/synac).  

# Example

```Rust
extern crate synac;

use synac::{Session, State};

fn main() {
    // TODO: Error checking
    let mut session = Session::new(env!("ADDR"), env!("HASH")).unwrap();
    session.login_with_token(true, env!("USERNAME"), env!("TOKEN")).unwrap(); // true specifies it's a bot account

    // First packet should be either LoginSuccess or an error
    let result = session.read().unwrap();
    // TODO: Use result

    let mut state = State::new();
    loop {
        let packet = session.read().unwrap();
        state.update(&packet);

        // TODO: Use packet
    }
}
```
