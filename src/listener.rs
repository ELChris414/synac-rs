use common::{self, Packet};
use error::Error;
use std::io::Read;

pub struct Listener {
    size: bool,
    buf:  Vec<u8>,
    i:    usize
}
impl Listener {
    /// Assuming `stream` is non blocking, `read` tries to read a packet.
    pub fn try_read<S: Read>(&mut self, stream: &mut S) -> Result<Option<Packet>, Error> {
        let read = stream.read(&mut self.buf[self.i..])?;
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
