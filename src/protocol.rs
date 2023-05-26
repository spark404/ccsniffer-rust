use std::borrow::Cow;
use std::error;
use std::fmt::{Display, Formatter};

pub struct Message<'a> {
    pub code: u8,
    pub length: u8,
    pub body: Cow<'a, [u8]>,
}

#[derive(Debug)]
pub enum ProtocolError {
    Other
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &*self {
            _ => write!(f, "protocol error")
        }
    }
}

impl error::Error for ProtocolError {}

impl<'a> Message<'a> {
    fn from_slice(mut slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < 5 {
            return Err(ProtocolError::Other)
        }

        Ok(Message{
            code: 0,
            length: 0,
            body: Default::default(),
        })
    }
}