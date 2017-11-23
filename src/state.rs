use common::*;
use std::collections::HashMap;

/// Holds track of stuff synac has sent locally.
pub struct State {
    pub channels: HashMap<usize, Channel>,
    pub groups:   HashMap<usize, Group>,
    pub users:    HashMap<usize, User>
}

impl State {
    /// Create new state
    pub fn new() -> Self {
        State {
            channels: HashMap::new(),
            groups:   HashMap::new(),
            users:    HashMap::new()
        }
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
            Packet::GroupDeleteReceive(ref event) => {
                for group in self.groups.values_mut() {
                    if group.pos > event.inner.pos {
                        group.pos -= 1;
                    }
                }
                self.groups.remove(&event.inner.id);
            },
            Packet::GroupReceive(ref event) => {
                if event.new {
                    if let Some(pos) = self.groups.get(&event.inner.id).map(|old| old.pos) {
                        if event.inner.pos > pos {
                            for group in self.groups.values_mut() {
                                if group.pos > pos && group.pos <= event.inner.pos {
                                    group.pos -= 1;
                                }
                            }
                        } else if event.inner.pos < pos {
                            for group in self.groups.values_mut() {
                                if group.pos >= event.inner.pos && group.pos < pos {
                                    group.pos += 1;
                                }
                            }
                        }
                    } else {
                        for group in self.groups.values_mut() {
                            if group.pos >= event.inner.pos {
                                group.pos += 1;
                            }
                        }
                    }
                }
                self.groups.insert(event.inner.id, event.inner.clone());
            },
            Packet::UserReceive(ref event) => {
                self.users.insert(event.inner.id, event.inner.clone());
            },
            _ => ()
        }
    }
}
