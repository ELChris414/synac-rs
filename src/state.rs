use common::*;
use std::collections::HashMap;

/// Holds track of stuff synac has sent locally.
pub struct State {
    pub channels: HashMap<usize, Channel>,
    pub groups:   HashMap<usize, Group>,
    pub users:    HashMap<usize, User>
}

impl State {
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
                for attr in self.groups.values_mut() {
                    if attr.pos > event.inner.pos {
                        attr.pos -= 1;
                    }
                }
                self.groups.remove(&event.inner.id);
            },
            Packet::GroupReceive(ref event) => {
                if event.new {
                    let pos = if let Some(old) = self.groups.get(&event.inner.id) {
                        Some(old.pos)
                    } else { None };
                    if let Some(pos) = pos {
                        if event.inner.pos > pos {
                            for attr in self.groups.values_mut() {
                                if attr.pos > pos && attr.pos <= event.inner.pos {
                                    attr.pos -= 1;
                                }
                            }
                        } else if event.inner.pos < pos {
                            for attr in self.groups.values_mut() {
                                if attr.pos >= event.inner.pos && attr.pos < pos {
                                    attr.pos += 1;
                                }
                            }
                        }
                    } else {
                        for attr in self.groups.values_mut() {
                            if attr.pos >= event.inner.pos {
                                attr.pos += 1;
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
