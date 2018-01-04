#[macro_use] extern crate failure;
extern crate openssl;
extern crate rmp_serde as rmps;

// Dependencies of common
#[macro_use] extern crate serde_derive;
// End

/// Files shared by both the client and server
pub mod common;
/// A non-blocking listener
pub mod listener;
/// Remembers stuff previous packets have informed about
pub mod state;

pub use listener::*;
pub use state::*;

use common::Packet;
use failure::Error;
use openssl::ssl::{SSL_VERIFY_PEER, SslConnectorBuilder, SslMethod, SslStream};
use openssl::x509::X509StoreContextRef;
use std::any::Any;
use std::fmt::Write;
use std::net::{TcpStream, ToSocketAddrs};

/// A struct that holds the connection to synac.
pub struct Session {
    stream: SslStream<TcpStream>
}

impl Session {
    /// Create a synac session that verifies the public key against a hash.
    pub fn new<S: Into<String>, T: ToSocketAddrs>(addr: T, hash: S) -> Result<Session, Error> {
        let hash = hash.into();
        Self::new_with_verify_callback(addr, move |_, cert| {
            if let Some(cert) = cert.current_cert() {
                if let Ok(pkey) = cert.public_key() {
                    if let Ok(pem) = pkey.public_key_to_pem() {
                        let digest = openssl::sha::sha256(&pem);
                        let mut digest_string = String::with_capacity(digest.len());
                        for byte in &digest {
                            write!(digest_string, "{:02X}", byte).unwrap();
                        }
                        use std::ascii::AsciiExt;
                        return hash.trim().eq_ignore_ascii_case(&digest_string);
                    }
                }
            }
            false
        })
    }
    /// Create a synac session with a custom SSL callback.
    pub fn new_with_verify_callback<T, F>(addr: T, callback: F)
        -> Result<Session, Error>
        where
            T: ToSocketAddrs,
            F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send
    {
        let mut config = SslConnectorBuilder::new(SslMethod::tls())?;
        config.set_verify_callback(SSL_VERIFY_PEER, callback);
        let connector = config.build();

        let stream = TcpStream::connect(addr)?;
        let stream =
connector.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)?;

        Ok(Session {
            stream: stream
        })
    }

    /// Returns inner connection
    pub fn inner_stream(&mut self) -> &mut SslStream<TcpStream> {
        &mut self.stream
    }

    /// Makes inner stream non-blocking
    pub fn set_nonblocking(&mut self, value: bool) -> Result<(), std::io::Error> {
        self.stream.get_ref().set_nonblocking(value)
    }

    /// Sends the login packet with specific password.
    /// Read the result with `read`.
    /// Warning: Strongly disencouraged. Use tokens instead, when possible.
    pub fn login_with_password<S: Into<String>>(&mut self, bot: bool, name: S, password: S) -> Result<(), Error> {
        self.send(&Packet::Login(common::Login {
            bot: bot,
            name: name.into(),
            password: Some(password.into()),
            token: None
        }))
    }
    /// Sends the login packet with specific token.
    /// Read the result with `read`.
    pub fn login_with_token<S: Into<String>>(&mut self, bot: bool, name: S, token: S) -> Result<(), Error> {
        self.send(&Packet::Login(common::Login {
            bot: bot,
            name: name.into(),
            password: None,
            token: Some(token.into())
        }))
    }

    /// Transmit a packet over the connection
    pub fn send(&mut self, packet: &Packet) -> Result<(), Error> {
        Ok(common::write(&mut self.stream, packet)?)
    }

    /// Read a packet from the connection
    pub fn read(&mut self) -> Result<Packet, Error> {
        Ok(common::read(&mut self.stream)?)
    }
}

/// Get the mode bitmask for a user in a channel
pub fn get_mode(channel: &common::Channel, user: &common::User) -> u8 {
    if user.bot {
        user.modes.get(&channel.id).cloned().unwrap_or(channel.default_mode_bot)
    } else {
        user.modes.get(&channel.id).cloned().unwrap_or(channel.default_mode_user)
    }
}
