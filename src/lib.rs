pub extern crate common;
extern crate openssl;
extern crate rmp_serde;

pub mod error;
pub mod state;

use openssl::ssl::{SSL_VERIFY_PEER, SslConnectorBuilder, SslMethod, SslStream};
use openssl::x509::X509StoreContextRef;
use std::any::Any;
use std::net::{TcpStream, ToSocketAddrs};

/// A struct that holds the connection to synac.
pub struct Session {
    pub conn: SslStream<TcpStream>
}

/// Create a synac session that verifies the public key against a hash.
pub fn new<T: ToSocketAddrs>(addr: T, hash: String) -> Result<Session, error::Error> {
    new_with_verify_callback(addr, move |_, cert| {
        if let Some(cert) = cert.current_cert() {
            if let Ok(pkey) = cert.public_key() {
                if let Ok(pem) = pkey.public_key_to_pem() {
                    let digest = openssl::sha::sha256(&pem);
                    let mut digest_string = String::with_capacity(digest.len());
                    for byte in &digest {
                        digest_string.push_str(&format!("{:0X}", byte));
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
        conn: stream
    })
}

impl Session {
    /// Transmit a message over the connection
    pub fn send(&mut self, packet: &common::Packet) -> Result<(), error::Error> {
        Ok(common::write(&mut self.conn, packet)?)
    }

    /// Read a packet from the connection
    pub fn read(&mut self) -> Result<common::Packet, error::Error> {
        Ok(common::read(&mut self.conn)?)
    }
}
