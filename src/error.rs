use common::Error as CommonError;
use openssl::error::ErrorStack as SslErrorStack;
use openssl::ssl::HandshakeError as SslHandshakeError;
use rmp_serde::decode::Error as DecodeError;
use rmp_serde::encode::Error as EncodeError;
use std::fmt;
use std::io::Error as IoError;
use std::net::TcpStream;

/// Different types of errors that can occur
#[derive(Debug)]
pub enum Error {
    DecodeError(DecodeError),
    EncodeError(EncodeError),
    PacketTooBigError,
    IoError(IoError),
    SslErrorStack(SslErrorStack),
    SslHandshakeError(SslHandshakeError<TcpStream>)
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::DecodeError(_)       => "Failed to decode MsgPack data",
            Error::EncodeError(_)       => "Failed to encode MsgPack data",
            Error::PacketTooBigError    => "Packet size must fit into an u16",
            Error::IoError(_)           => "An IO operation failed",
            Error::SslErrorStack(_)     => "An SSL operation failed",
            Error::SslHandshakeError(_) => "SSL handshake failed"
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error as SomeTypeThatWontInterfere;
        match *self {
            Error::DecodeError(ref inner)       => write!(f, "DecodeError: {}", inner),
            Error::EncodeError(ref inner)       => write!(f, "EncodeError: {}", inner),
            Error::PacketTooBigError            => write!(f, "{}", self.description()),
            Error::IoError(ref inner)           => write!(f, "IoError: {}", inner),
            Error::SslErrorStack(ref inner)     => write!(f, "SslErrorStack: {}", inner),
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
    DecodeError as Error::DecodeError,
    EncodeError as Error::EncodeError,
    IoError as Error::IoError,
    SslErrorStack as Error::SslErrorStack,
    SslHandshakeError<TcpStream> as Error::SslHandshakeError
);
impl From<CommonError> for Error {
    fn from(error: CommonError) -> Self {
        match error {
            CommonError::DecodeError(inner) => Error::DecodeError(inner),
            CommonError::EncodeError(inner) => Error::EncodeError(inner),
            CommonError::PacketTooBigError  => Error::PacketTooBigError,
            CommonError::IoError(inner)     => Error::IoError(inner)
        }
    }
}
