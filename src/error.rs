use openssl::error::ErrorStack as SslErrorStack;
use openssl::ssl::HandshakeError as SslHandshakeError;
use std::fmt;
use std::io::Error as IOError;
use std::net::TcpStream;

/// Different types of errors that can occur
#[derive(Debug)]
pub enum Error {
    IOError(IOError),
    SslErrorStack(SslErrorStack),
    SslHandshakeError(SslHandshakeError<TcpStream>)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IOError(ref inner) => write!(f, "IOError: {}", inner),
            Error::SslErrorStack(ref inner) => write!(f, "SslErrorStack: {}", inner),
            Error::SslHandshakeError(ref inner) => write!(f, "SslHandshakeError: {}", inner)
        }
    }
}
macro_rules! impl_from {
    ($($type:ty as $path:path),+) => {
        $(
            impl From<$type> for Error {
                fn from(error: $type) -> Self {
                    $path(error)
                }
            }
        )+
    }
}
impl_from! (
    IOError as Error::IOError,
    SslErrorStack as Error::SslErrorStack,
    SslHandshakeError<TcpStream> as Error::SslHandshakeError
);
