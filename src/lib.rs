#[cfg(feature = "tokio")] extern crate futures;
#[cfg(feature = "tokio")] extern crate tokio_core;
#[cfg(feature = "tokio")] extern crate tokio_io;
#[cfg(feature = "tokio")] extern crate tokio_openssl;
#[macro_use] extern crate failure;
extern crate openssl;
extern crate rmp_serde as rmps;

// Dependencies of common
#[macro_use] extern crate serde_derive;
// End

/// Files shared by both the client and server
pub mod common;
#[cfg(not(feature = "tokio"))]
/// A non-blocking listener
pub mod listener;
/// Remembers stuff previous packets have informed about
pub mod state;

#[cfg(not(feature = "tokio"))] pub use listener::*;
pub use state::*;

#[cfg(feature = "tokio")] use futures::{future, Future};
#[cfg(feature = "tokio")] use std::net::SocketAddr;
#[cfg(feature = "tokio")] use std::rc::Rc;
#[cfg(feature = "tokio")] use tokio_core::net::TcpStream;
#[cfg(feature = "tokio")] use tokio_core::reactor::Handle;
#[cfg(feature = "tokio")] use tokio_io::{io, AsyncRead};
#[cfg(feature = "tokio")] use tokio_openssl::{ConnectConfigurationExt, SslStream};
#[cfg(not(feature = "tokio"))] use openssl::ssl::SslStream;
#[cfg(not(feature = "tokio"))] use std::net::TcpStream;
#[cfg(not(feature = "tokio"))] use std::net::ToSocketAddrs;
use common::Packet;
use failure::Error;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509StoreContextRef;
use std::any::Any;
use std::fmt::Write;

pub type Stream = SslStream<TcpStream>;

#[cfg(not(feature = "tokio"))]
/// A struct that holds the connection to synac.
pub struct Session {
    stream: Stream
}

#[cfg(feature = "tokio")]
/// A struct that holds the connection to synac.
pub struct Session {
    reader: Option<io::ReadHalf<Stream>>,
    writer: io::WriteHalf<Stream>
}

impl Session {
    #[cfg(not(feature = "tokio"))]
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
                        return hash.trim().eq_ignore_ascii_case(&digest_string);
                    }
                }
            }
            false
        })
    }
    #[cfg(feature = "tokio")]
    /// Create a synac session that verifies the public key against a hash.
    pub fn new<S: Into<String>>(addr: &SocketAddr, hash: S, handle: &Handle)
        -> Box<Future<Item = Session, Error = Error>>
    {
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
                        return hash.trim().eq_ignore_ascii_case(&digest_string);
                    }
                }
            }
            false
        }, handle)
    }

    #[cfg(not(feature = "tokio"))]
    /// Create a synac session with a custom SSL callback.
    pub fn new_with_verify_callback<T, F>(addr: T, callback: F)
        -> Result<Session, Error>
        where
            T: ToSocketAddrs,
            F: Fn(bool, &mut X509StoreContextRef) -> bool + Any + 'static + Sync + Send
    {
        let mut config = SslConnector::builder(SslMethod::tls())?;
        config.set_verify_callback(SslVerifyMode::PEER, callback);
        let connector = config.build();

        let stream = TcpStream::connect(addr)?;
        let stream = connector.configure()?
                        .use_server_name_indication(false)
                        .verify_hostname(false)
                        .connect("", stream)?;

        Ok(Session {
            stream: stream
        })
    }
    #[cfg(feature = "tokio")]
    /// Create a synac session with a custom SSL callback.
    pub fn new_with_verify_callback<F>(addr: &SocketAddr, callback: F, handle: &Handle)
        -> Box<Future<Item = Session, Error = Error>>
        where
            F: Fn(bool, &mut X509StoreContextRef) -> bool + Any + 'static + Sync + Send
    {
        let mut config = match SslConnector::builder(SslMethod::tls()) {
            Ok(config) => config,
            Err(err) => return Box::new(future::err(Error::from(err)))
        };
        config.set_verify_callback(SslVerifyMode::PEER, callback);
        let connector = config.build();

        Box::new(TcpStream::connect(addr, handle)
            .map_err(Error::from)
            .and_then(move |stream| -> Box<Future<Item = Session, Error = Error>> {
                let config = match connector.configure() {
                    Ok(config) => config,
                    Err(err) => return Box::new(future::err(Error::from(err)))
                };
                Box::new(config
                    .use_server_name_indication(false)
                    .verify_hostname(false)
                    .connect_async("", stream)
                    .map_err(Error::from)
                    .map(|stream| {
                        let (reader, writer) = stream.split();
                        Session {
                            reader: Some(reader),
                            writer: writer
                        }
                    }))
        }))
    }

    #[cfg(not(feature = "tokio"))]
    /// Returns inner connection
    pub fn inner_stream(&mut self) -> &mut Stream {
        &mut self.stream
    }

    #[cfg(not(feature = "tokio"))]
    /// Makes inner stream non-blocking
    pub fn set_nonblocking(&mut self, value: bool) -> Result<(), std::io::Error> {
        self.stream.get_ref().set_nonblocking(value)
    }

    /// Sends the login packet with specific password.
    /// Read the result with `read`.
    /// Warning: Strongly disencouraged. Use tokens instead, when possible.
    pub fn login_with_password<S: Into<String>>(&mut self, bot: bool, name: S, password: S) -> Result<(), Error> {
        self.write(&Packet::Login(common::Login {
            bot: bot,
            name: name.into(),
            password: Some(password.into()),
            token: None
        }))
    }
    /// Sends the login packet with specific token.
    /// Read the result with `read`.
    pub fn login_with_token<S: Into<String>>(&mut self, bot: bool, name: S, token: S) -> Result<(), Error> {
        self.write(&Packet::Login(common::Login {
            bot: bot,
            name: name.into(),
            password: None,
            token: Some(token.into())
        }))
    }

    #[cfg(not(feature = "tokio"))]
    /// Transmit a packet over the connection
    pub fn write(&mut self, packet: &Packet) -> Result<(), Error> {
        Ok(common::write(&mut self.stream, packet)?)
    }
    #[cfg(feature = "tokio")]
    /// Transmit a packet over the connection
    pub fn write(&mut self, packet: &Packet) -> Result<(), Error> {
        Ok(common::write(&mut self.writer, packet)?)
    }

    #[cfg(not(feature = "tokio"))]
    /// Read a packet from the connection
    pub fn read(&mut self) -> Result<Packet, Error> {
        Ok(common::read(&mut self.stream)?)
    }
    #[cfg(feature = "tokio")]
    /// Read a packet from the connection
    pub fn read_loop<F: Fn(Packet) + 'static>(&mut self, callback: F)
        -> Box<Future<Item = (), Error = Error>> // TODO: impl Future
    {
        let reader = self.reader.take().expect("A read loop already exists");
        let callback = Rc::new(callback);

        Box::new(future::loop_fn(reader, move |reader| {
            let callback = Rc::clone(&callback);

            io::read_exact(reader, [0; 2])
                .map_err(Error::from)
                .and_then(move |(reader, buf)| {
                    let callback = Rc::clone(&callback);
                    let size = common::decode_u16(&buf);

                    io::read_exact(reader, vec![0; size as usize])
                        .map_err(Error::from)
                        .and_then(move |(reader, buf)| {
                            let packet = match common::deserialize(&buf) {
                                Ok(packet) => packet,
                                Err(err) => return Err(err.into())
                            };
                            callback(packet);
                            Ok(future::Loop::Continue(reader))
                        })
                })
        }))
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
