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

    /// Search for a private channel with user
    pub fn get_private_channel<'a>(&'a self, user: &User) -> Option<&'a Channel> {
        user.modes.keys()
            .filter_map(|channel| self.channels.get(&channel))
            .find(|channel| channel.private)
        // the server doesn't send PMs you don't have access to
    }

    /// Search for the recipient in a private channel
    pub fn get_recipient(&self, channel: &Channel) -> Option<&User> {
        if channel.private { return None; }
        self.get_recipient_unchecked(channel.id)
    }

    /// Search for the recipient in a private channel.
    /// If the channel isn't private, it returns the first user it can find
    /// that has a special mode in that channel.
    /// So you should probably make sure it's private first.
    pub fn get_recipient_unchecked(&self, channel_id: usize) -> Option<&User> {
        self.users.values()
            .find(|user| (**user).modes.keys()
                .find(|channel| **channel == channel_id)
                .is_some())
    }
}
