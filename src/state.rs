use common::*;
use std::collections::HashMap;

/// A struct that remembers stuff previous packets have informed about
pub struct State {
    pub channels: HashMap<usize, Channel>,
    pub users:    HashMap<usize, User>
}

impl Default for State {
    fn default() -> Self {
        State {
            channels: HashMap::new(),
            users:    HashMap::new()
        }
    }
}
impl State {
    /// Create new state
    pub fn new() -> Self {
        State::default()
    }
    /// Update the state with `packet`
    pub fn update(&mut self, packet: &Packet) {
        match *packet {
            Packet::ChannelDeleteReceive(ref event) => {
                self.channels.remove(&event.inner.id);
            },
            Packet::ChannelReceive(ref event) => {
                self.channels.insert(event.inner.id, event.inner.clone());
            },
            Packet::UserReceive(ref event) => {
                self.users.insert(event.inner.id, event.inner.clone());
            },
            _ => ()
        }
    }
}
