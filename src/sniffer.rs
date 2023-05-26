use hxdmp::hexdump;
use rusb::Direction::{In, Out};
use rusb::{
    Device, DeviceDescriptor, DeviceHandle, DeviceList, Direction, EndpointDescriptor,
    GlobalContext, InterfaceDescriptor,
};
use std::fmt::Debug;
use std::time::Duration;
use std::{error, fmt};

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
    descriptor: DeviceDescriptor,
    out_address: u8,
    in_address: u8,
    debug: bool,
}

#[derive(Debug)]
pub enum SnifferError {
    DeviceError,
    ProtocolError(&'static str),
    TimeOut,
    UsbError(rusb::Error),
}

impl fmt::Display for SnifferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            SnifferError::DeviceError => write!(f, "module error in the sniffer module"),
            SnifferError::ProtocolError(detail) => write!(f, "protocol error: {}", detail),
            SnifferError::TimeOut => write!(f, "time out"),
            SnifferError::UsbError(e) => {
                write!(f, "usb error: {}", e.to_string())
            }
        }
    }
}

impl From<rusb::Error> for SnifferError {
    fn from(e: rusb::Error) -> Self {
        return SnifferError::UsbError(e);
    }
}

impl error::Error for SnifferError {}

impl SnifferDevice {
    pub fn new(device: Device<GlobalContext>) -> Result<SnifferDevice, Box<dyn error::Error>> {
        let mut handle = device.open()?;
        let descriptor = device.device_descriptor()?;

        handle.claim_interface(0)?;

        let config_desc = device.active_config_descriptor()?;

        // Should have one interface
        let interface = config_desc.interfaces().next().unwrap();
        let interface_descriptor = interface.descriptors().next().unwrap();
        let in_endpoint = find_first_endpoint(&interface_descriptor, In)?;
        let out_endpoint = find_first_endpoint(&interface_descriptor, Out)?;

        return Ok(SnifferDevice {
            handle,
            descriptor,
            out_address: out_endpoint.address(),
            in_address: in_endpoint.address(),
            debug: false,
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
        match self.handle.read_product_string_ascii(&self.descriptor) {
            Ok(n) => Some(n),
            Err(_e) => None,
        }
    }

    pub fn send_command(&self, command: CmdCodes, payload: &[u8]) -> Result<(), SnifferError> {
        let mut buffer = vec![];

        let payload_len = payload.len();
        let ack: CmdCodes = (command as u8 + 1).into(); // hack, ack is command + 1 in the enum

        buffer.push((3 + payload_len) as u8); // length
        buffer.push(command as u8); // command
        buffer.append(&mut payload.to_vec());
        buffer.push(calculate_crc(buffer.as_slice(), payload_len + 2)); //checksum

        if self.debug {
            dump(buffer.as_slice(), buffer.len());
        }

        let bytes_written = self
            .handle
            .write_bulk(
                self.out_address,
                &buffer[0..buffer[0] as usize],
                Duration::from_millis(250),
            )
            .or_else(|e| return Err(SnifferError::UsbError(e)))?;

        if bytes_written != buffer.len() {
            return Err(SnifferError::DeviceError);
        }

        let mut read_buffer = vec![0; 256];
        match self.handle.read_bulk(
            self.in_address,
            read_buffer.as_mut_slice(),
            Duration::from_millis(250),
        ) {
            Ok(n) => {
                if n == 0 {
                    return Err(SnifferError::DeviceError);
                }

                if self.debug {
                    dump(read_buffer.as_slice(), (read_buffer[0] + 1) as usize);
                    // Byte extra for total length
                }

                if read_buffer[2] != ack as u8 {
                    return Err(SnifferError::ProtocolError("unexpected response code"));
                }

                Ok(())
            }
            Err(e) => Err(SnifferError::UsbError(e)),
        }
    }

    pub fn receive_packet(&self) -> Result<Vec<u8>, SnifferError> {
        let mut buffer = vec![0; 256];

        let read_result = self.handle.read_bulk(
            self.in_address,
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
                    return Err(SnifferError::ProtocolError("empty read"));
                }

                if buffer[0] != buffer[1] {
                    // Shouldn't happen with my version of the firmware
                    return Err(SnifferError::ProtocolError("size mismatch"));
                }

                if self.debug {
                    dump(buffer.as_slice(), buffer[0] as usize);
                }

                if buffer[2] != CmdCodes::CmdGotPkt as u8 {
                    println!("Unexpected result {:#04x}", buffer[2]);
                    return Err(SnifferError::ProtocolError("Unexpected command code"));
                }

                buffer.drain((n - 1)..); // Drop the unused part
                buffer.drain(..3); // Drop the metadata
                Ok(buffer)
            }
            Err(e) => match e {
                rusb::Error::Timeout => Err(SnifferError::TimeOut),
                _ => Err(e.into()),
            },
        }
    }

    pub fn set_debug(&mut self) {
        self.debug = true;
    }
}

// Procedure copied from the firmware
fn calculate_crc(buffer: &[u8], len: usize) -> u8 {
    let mut checksum = 0xff;
    for i in 0..len {
        checksum ^= buffer[i as usize];
    }
    return checksum;
}

fn dump(buffer: &[u8], len: usize) {
    let mut outbuf = Vec::new();
    hexdump(&buffer[0..len as usize], &mut outbuf).expect("hexdump issue");
    println!("{}", String::from_utf8_lossy(&outbuf))
}

fn find_first_endpoint<'a>(
    interface_descriptor: &'a InterfaceDescriptor<'a>,
    direction: Direction,
) -> Result<EndpointDescriptor, Box<SnifferError>> {
    return interface_descriptor
        .endpoint_descriptors()
        .find(|endpoint| {
            return endpoint.direction() == direction;
        })
        .ok_or_else(|| Box::new(SnifferError::DeviceError));
}
