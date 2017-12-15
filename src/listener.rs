use common::{self, Packet};
use failure::Error;
use std::io::{ErrorKind as IoErrorKind, Read};

/// A non-blocking listener
pub struct Listener {
    size: bool,
    buf:  Vec<u8>,
    i:    usize
}
impl Default for Listener {
    fn default() -> Self {
        Listener {
            size: true,
            buf:  vec![0; 2],
            i:    0
        }
    }
}
impl Listener {
    /// Creates new Listener
    pub fn new() -> Self {
        Listener::default()
    }
    /// Assuming `stream` is non blocking, `read` tries to read a packet, returning `None` if not possible.
    pub fn try_read<S: Read>(&mut self, stream: &mut S) -> Result<Option<Packet>, Error> {
        let read = match stream.read(&mut self.buf[self.i..]) {
            Ok(read) => read,
            Err(ref err)
                if err.kind() == IoErrorKind::WouldBlock
                => return Ok(None),
            Err(err) => return Err(err.into())
        };
        if read == 0 {
            return Ok(None);
        }
        self.i += read;

        if self.i >= self.buf.len() {
            if self.size {
                self.size = false;
                let size = common::decode_u16(&self.buf) as usize;
                self.buf = vec![0; size];
                self.i = 0;
            } else {
                let packet = common::deserialize(&self.buf)?;

                self.size = true;
                self.buf = vec![0; 2];
                self.i = 0;
                return Ok(Some(packet));
            }
        }
        Ok(None)
    }
}
