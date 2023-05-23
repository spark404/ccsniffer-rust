use hxdmp::hexdump;
use rusb::Direction::{In, Out};
use rusb::{Device, DeviceDescriptor, DeviceHandle, DeviceList, GlobalContext};
use std::time::Duration;
use std::{error, fmt};
use crate::sniffer::SnifferError::DeviceError;

#[repr(u8)]
#[derive(PartialEq, PartialOrd, Clone, Copy)]
pub enum CmdCodes {
    CmdInit = 0x00,
    CmdInitAck = 0x01,
    CmdSetChannel = 0x02,
    CmdSetChannelAck = 0x03,
    CmdSendPkt = 0x04,
    CmdSendPktAck = 0x05,
    CmdSniffOn = 0x06,
    CmdSniffOnAck = 0x07,
    CmdSniffOff = 0x08,
    CmdSniffOffAck = 0x09,
    CmdGotPkt = 0x0A,
    CmdErr = 0xFF,
}

impl From<u8> for CmdCodes {
    fn from(orig: u8) -> Self {
        return match orig {
            0x00 => CmdCodes::CmdInit,
            0x01 => CmdCodes::CmdInitAck,
            0x02 => CmdCodes::CmdSetChannel,
            0x03 => CmdCodes::CmdSetChannelAck,
            0x04 => CmdCodes::CmdSendPkt,
            0x05 => CmdCodes::CmdSendPktAck,
            0x06 => CmdCodes::CmdSniffOn,
            0x07 => CmdCodes::CmdSniffOnAck,
            0x08 => CmdCodes::CmdSniffOff,
            0x09 => CmdCodes::CmdSniffOffAck,
            0x0A => CmdCodes::CmdGotPkt,
            0xFF => CmdCodes::CmdErr,
            _ => return CmdCodes::CmdErr,
        };
    }
}

pub struct SnifferDevice {
    handle: DeviceHandle<GlobalContext>,
    _descriptor: DeviceDescriptor,
    out_address: u8,
    in_address: u8,
    debug: bool
}

#[derive(Debug)]
enum SnifferError {
    DeviceError,
    ProtocolError(&'static str),
    TimeOut,
}

impl fmt::Display for SnifferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            SnifferError::DeviceError =>
                write!(f, "module error in the sniffer module"),
            SnifferError::ProtocolError(detail) =>
                write!(f, "protocol error: {}", detail),
            SnifferError::TimeOut =>
                write!(f, "time out")
        }
    }
}

impl error::Error for SnifferError {}

impl SnifferDevice {
    pub fn new(device: Device<GlobalContext>) -> Result<SnifferDevice, Box<dyn error::Error>> {
        let mut device_handle = device.open()?;
        let descriptor = device.device_descriptor()?;

        device_handle.claim_interface(0)?;

        let config_desc = device
            .active_config_descriptor()?;

        // Should have one interface
        let interface = config_desc.interfaces().next().unwrap();
        let interface_descriptor = interface.descriptors().next().unwrap();

        let in_endpoint = interface_descriptor
            .endpoint_descriptors()
            .find(|endpoint| {
                return endpoint.direction() == In;
            })
            .ok_or_else(|| Box::new(DeviceError))?;

        let out_endpoint = interface_descriptor
            .endpoint_descriptors()
            .find(|endpoint| {
                return endpoint.direction() == Out;
            })
            .ok_or_else(|| Box::new(DeviceError))?;

        return Ok(SnifferDevice {
            handle: device_handle,
            _descriptor: descriptor,
            out_address: out_endpoint.address(),
            in_address: in_endpoint.address(),
            debug: false
        });
    }

    pub fn find_device(vendor: u16, product: u16) -> Option<Device<GlobalContext>> {
        DeviceList::new().unwrap().iter().find_map(|d| {
            let device_desc = d.device_descriptor().expect(&*format!(
                "Failed to get device descriptor for device {}:{}:{}",
                d.bus_number(),
                d.port_number(),
                d.address()
            ));

            if device_desc.vendor_id() == vendor && device_desc.product_id() == product {
                return Some(d);
            }
            return None;
        })
    }

    pub fn get_product_name(&self) -> Option<String> {
        match self.handle.read_product_string_ascii(&self._descriptor) {
            Ok(n) => Some(n),
            Err(_e) => None,
        }
    }

    pub fn send_command(&self, command: CmdCodes, payload: &[u8]) {
        let mut buffer = vec![0; 256];

        let payload_len = payload.len();
        let ack: CmdCodes = (command as u8 + 1).into(); // hack, ack is command + 1 in the enum

        buffer[0] = (3 + payload_len) as u8; // length
        buffer[1] = command as u8; // command
        buffer[2..payload_len + 2].copy_from_slice(payload);
        buffer[payload_len + 2] = calculate_crc(buffer.as_slice(), buffer[0]); //checksum

        let _write_result = self.handle.write_bulk(
            self.out_address,
            &buffer[0..buffer[0] as usize],
            Duration::from_millis(250),
        );
        dump(&buffer, buffer[0]);

        let read_result = self.handle.read_bulk(
            self.in_address,
            buffer.as_mut_slice(),
            Duration::from_millis(250),
        );
        match read_result {
            Ok(n) => {
                if n == 0 {
                    println!("weird, no bytes read");
                }
                dump(buffer.as_slice(), buffer[0] + 1); // Byte extra for total length
                if buffer[2] != ack as u8 {
                    println!("Unexpected result {:#04x}", buffer[2]);
                    return;
                }
                println!("Acknowledged")
            }
            Err(e) => {
                println!("read failed: {e}");
            }
        }
    }

    pub fn receive_packet(&self) -> Result<Vec<u8>, Box<dyn error::Error>> {
        let mut buffer = vec![0; 256];

        let read_result = self.handle.read_bulk(self.in_address,
            buffer.as_mut_slice(),
            Duration::from_millis(1000),
        );

        match read_result {
            Ok(n) => {
                // We should have received data in the following format
                // [0] = USB data size
                // [1] = Protocol packet length
                // [2] = Command code
                // [3] = RSSI
                // [4] = Link Quality
                // [..] = Raw packet
                // [len-1] = Checksum - last byte is a checksum

                if n == 0 {
                    return Err(Box::new(SnifferError::ProtocolError("empty read")))
                }

                if buffer[0] != buffer[1] {
                    // Shouldn't happen with my version of the firmware
                    return Err(Box::new(SnifferError::ProtocolError("size mismatch")));
                }

                if self.debug {
                    dump(buffer.as_slice(), buffer[0]);
                }

                if buffer[2] != CmdCodes::CmdGotPkt as u8{
                    println!("Unexpected result {:#04x}", buffer[2]);
                    return Err(Box::new(SnifferError::ProtocolError("Unexpected command code")));
                }

                buffer.drain((n-1)..); // Drop the unused part
                buffer.drain(..5); // Drop the metadata
                Ok(buffer)
            },
            Err(e) => match e {
                rusb::Error::Timeout => Err(Box::new(SnifferError::TimeOut)),
                _ => Err(e.into())
            }
        }
    }
}

// Procedure copied from the firmware
fn calculate_crc(buffer: &[u8], len: u8) -> u8 {
    let mut checksum = 0xff;
    for i in 0..len {
        checksum ^= buffer[i as usize];
    }
    return checksum;
}

fn dump(buffer: &[u8], len: u8) {
    let mut outbuf = Vec::new();
    hexdump(&buffer[0..len as usize], &mut outbuf).expect("hexdump issue");
    println!("{}", String::from_utf8_lossy(&outbuf))
}
