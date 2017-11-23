pub extern crate common;
extern crate openssl;
extern crate rmp_serde;

pub mod error;
pub mod listener;
pub mod state;

use common::Packet;
use error::Error;
use openssl::ssl::{SSL_VERIFY_PEER, SslConnectorBuilder, SslMethod, SslStream};
use openssl::x509::X509StoreContextRef;
use std::any::Any;
use std::net::{TcpStream, ToSocketAddrs};

/// A struct that holds the connection to synac.
pub struct Session {
    stream: SslStream<TcpStream>
}

/// Create a synac session that verifies the public key against a hash.
pub fn new<T: ToSocketAddrs>(addr: T, hash: String) -> Result<Session, Error> {
    new_with_verify_callback(addr, move |_, cert| {
        if let Some(cert) = cert.current_cert() {
            if let Ok(pkey) = cert.public_key() {
                if let Ok(pem) = pkey.public_key_to_pem() {
                    let digest = openssl::sha::sha256(&pem);
                    let mut digest_string = String::with_capacity(digest.len());
                    for byte in &digest {
                        digest_string.push_str(&format!("{:02X}", byte));
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
    -> Result<Session, error::Error>
    where
        T: ToSocketAddrs,
        F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send
{
    let mut config = SslConnectorBuilder::new(SslMethod::tls())?;
    config.builder_mut().set_verify_callback(SSL_VERIFY_PEER, callback);
    let connector = config.build();

    let stream = TcpStream::connect(addr)?;
    let stream =
connector.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)?;

    Ok(Session {
        stream: stream
    })
}

impl Session {
    /// Returns inner connection
    pub fn inner_stream(&mut self) -> &mut SslStream<TcpStream> {
        &mut self.stream
    }

    /// Sends the login packet with specific password.
    /// Read the result with `read`.
    /// Warning: Strongly disencouraged. Use tokens instead, when possible.
    pub fn login_with_password(&mut self, bot: bool, name: String, password: String) -> Result<(), Error> {
        self.send(&Packet::Login(common::Login {
            bot: bot,
            name: name,
            password: Some(password),
            token: None
        }))
    }
    /// Sends the login packet with specific token.
    /// Read the result with `read`.
    pub fn login_with_token(&mut self, bot: bool, name: String, token: String) -> Result<(), Error> {
        self.send(&Packet::Login(common::Login {
            bot: bot,
            name: name,
            password: None,
            token: Some(token)
        }))
    }

    /// Transmit a message over the connection
    pub fn send(&mut self, packet: &Packet) -> Result<(), Error> {
        Ok(common::write(&mut self.stream, packet)?)
    }

    /// Read a packet from the connection
    pub fn read(&mut self) -> Result<Packet, Error> {
        Ok(common::read(&mut self.stream)?)
    }
}
