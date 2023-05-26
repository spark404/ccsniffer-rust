use byteorder_slice::byteorder::WriteBytesExt;
use byteorder_slice::LittleEndian;
use std::io;
use std::io::Write;

pub enum TapBlock {
    Header(usize),
    TlvRssi(f32),
    TlvLqi(u8),
    ChannelAssignment(u16)
}

#[repr(u16)]
enum Tlv {
    RSSI = 1,
    ChannelAssignment = 3,
    LQI = 10,
}

impl TapBlock {
    pub fn write_to<W: Write>(self, w: &mut W) -> io::Result<usize> {
        match self {
            TapBlock::TlvRssi(v) => {
                w.write_u16::<LittleEndian>(Tlv::RSSI as u16)?;
                w.write_u16::<LittleEndian>(4)?;
                w.write_f32::<LittleEndian>(v)?;
                Ok(8)
            }
            TapBlock::TlvLqi(v) => {
                w.write_u16::<LittleEndian>(Tlv::LQI as u16)?;
                w.write_u16::<LittleEndian>(1)?;
                w.write_u8(v)?;
                let padding = [0 as u8, 0, 0];
                w.write(&padding)?; // padding
                Ok(8)
            }
            TapBlock::Header(blocks) => {
                w.write_u8(0)?; // version
                w.write_u8(0)?;
                w.write_u16::<LittleEndian>(4 + 8 * (blocks as u16))?;
                Ok(4)
            }
            TapBlock::ChannelAssignment(channel) => {
                w.write_u16::<LittleEndian>(Tlv::ChannelAssignment as u16)?;
                w.write_u16::<LittleEndian>(3)?;
                w.write_u16::<LittleEndian>(channel)?;
                w.write_u8(0)?; // Channel page?
                w.write_u8(0)?; // padding
                Ok(8)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pcaptap::TapBlock;

    #[test]
    fn serialize_header() {
        let mut v = vec![1 as u8; 0];
        TapBlock::Header(2).write_to(&mut v).expect("Failed");
        assert_eq!(v, [0, 0, 20, 0])
    }

    #[test]
    fn serialize_rssi() {
        let mut v = vec![1 as u8; 0];
        TapBlock::TlvRssi(5.0).write_to(&mut v).expect("Failed");
        assert_eq!(v, [1, 0, 4, 0, 0, 0, 160, 64])
    }

    #[test]
    fn serialize_lqi() {
        let mut v = vec![1 as u8; 0];
        TapBlock::TlvLqi(5).write_to(&mut v).expect("Failed");
        assert_eq!(v, [10, 0, 1, 0, 5, 0, 0, 0])
    }

    #[test]
    fn serialize_ca() {
        let mut v = vec![1 as u8; 0];
        TapBlock::ChannelAssignment(11).write_to(&mut v).expect("Failed");
        assert_eq!(v, [3, 0, 3, 0, 11, 0, 0, 0])
    }
}
