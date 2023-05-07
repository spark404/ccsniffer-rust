use std::borrow::Cow;
use std::fs::File;
use crate::CmdCodes::{CmdGotPkt, CmdInit, CmdSetChannel, CmdSniffOn};
use crc::{Crc, CRC_16_XMODEM};
use rusb::{DeviceDescriptor, DeviceHandle, DeviceList, GlobalContext};
use rusb::Direction::{In, Out};
use std::process::exit;
use std::time::Duration;
use hxdmp::hexdump;
use pcap_file::DataLink;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};

pub const CRC_16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);

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
            0x00 => CmdInit,
            0x01 => CmdCodes::CmdInitAck,
            0x02 => CmdSetChannel,
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



struct SnifferDevice {
    handle: DeviceHandle<GlobalContext>,
    descriptor: DeviceDescriptor,
    out_address: u8,
    in_address: u8
}

fn main() {
    println!("CCSniffer");

    let file = File::create("out.pcap").expect("Error creating file");
    let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();

    let devices = DeviceList::new().unwrap().iter().find_map(|d| {
        let device_desc = d
            .device_descriptor()
            .expect("Failed to get device descriptor");

        if device_desc.vendor_id() == 0x0451 && device_desc.product_id() == 0x16a8 {
            return Some(d);
        }
        return None;
    });

    let sniffer_device = match devices {
        Some(d) => d,
        None => {
            println!("No sniffer devices found");
            exit(1);
        }
    };

    let mut sniffer = match sniffer_device.open() {
        Ok(handle) => handle,
        Err(e) => {
            println!("Failed to open device {e}");
            exit(1);
        }
    };

    let product = sniffer
        .read_product_string_ascii(&sniffer_device.device_descriptor().unwrap())
        .unwrap();
    println!("Found {product}");

    sniffer
        .claim_interface(0)
        .expect("Claim of interface 0 failed");

    let config_desc = sniffer_device
        .active_config_descriptor()
        .expect("Failed to get configuration descriptor or no active config");

    // Should have one interface
    let interface = config_desc.interfaces().next().unwrap();
    let interface_descriptor = interface.descriptors().next().unwrap();

    let in_endpoint = interface_descriptor
        .endpoint_descriptors()
        .find(|endpoint| {
            return endpoint.direction() == In;
        })
        .unwrap();

    let out_endpoint = interface_descriptor
        .endpoint_descriptors()
        .find(|endpoint| {
            return endpoint.direction() == Out;
        })
        .unwrap();

    let sniffer_device = SnifferDevice {
        handle: sniffer,
        descriptor: sniffer_device.device_descriptor().unwrap(),
        in_address: in_endpoint.address(),
        out_address: out_endpoint.address()
    };

    println!("Send CmdInit");
    send_command(&sniffer_device, CmdInit, &[]);

    println!("Send CmdSetChannel 15");
    send_command(&sniffer_device, CmdSetChannel, vec![15].as_slice());

    println!("Send CmdSniffOn");
    send_command(&sniffer_device, CmdSniffOn, &[]);

    println!("Looping over received packets");
    let mut buffer = vec![0; 256];
    let mut remaining = 0;
    loop {
        let read_result = sniffer_device.handle.read_bulk(
            sniffer_device.in_address,
            buffer.as_mut_slice(),
            Duration::from_millis(1000),
        );
        match read_result {
            Ok(n) => {
                if n == 0 {
                    println!("weird, no bytes read");
                }

                if remaining == 0 {
                    // Ready for next packet
                    remaining = buffer[1];
                }

                if remaining < buffer[0] {
                    println!("possible data loss, reset counter");
                    remaining = buffer[1];
                }

                dump(buffer.as_slice(), buffer[0]);
                remaining -= buffer[0];

                let idb = InterfaceDescriptionBlock {
                    linktype: DataLink::IEEE802_15_4_NOFCS,
                    snaplen: 0xFFFF,
                    options: vec![],
                };

                let packet = EnhancedPacketBlock {
                    interface_id: 0,
                    timestamp: Duration::from_secs(0),
                    original_len: (buffer[0] - 4) as u32,
                    data: Cow::Borrowed(&buffer[4..buffer[0] as usize]),
                    options: vec![],
                };

                pcap_ng_writer.write_block(&idb.into_block()).unwrap();
                pcap_ng_writer.write_block(&packet.into_block()).unwrap();

                if buffer[2] != CmdGotPkt as u8 && remaining == 0 {
                    println!("Unexpected result {:#04x}", buffer[2]);
                    return;
                }
            }
            Err(e) => {
                println!("read failed: {e}");
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
    hexdump(&buffer[0..len as usize], &mut outbuf)
        .expect("hexdump issue");
    println!("{}", String::from_utf8_lossy(&outbuf))
}

fn send_command(sniffer: &SnifferDevice, command: CmdCodes, payload: &[u8]) {
    let mut buffer = vec![0; 256];

    let payload_len = payload.len();
    let ack: CmdCodes = (command as u8 + 1).into();  // hack, ack is command + 1 in the enum

    buffer[0] = (3 + payload_len) as u8; // length
    buffer[1] = command as u8; // command
    buffer[2..payload_len+2].copy_from_slice(payload);
    buffer[payload_len+2] = calculate_crc(buffer.as_slice(), buffer[0]); //checksum

    let _write_result = sniffer.handle.write_bulk(
        sniffer.out_address,
        &buffer[0..buffer[0] as usize],
        Duration::from_millis(250),
    );
    dump(&buffer, buffer[0]);


    let read_result = sniffer.handle.read_bulk(
        sniffer.in_address,
        buffer.as_mut_slice(),
        Duration::from_millis(250),
    );
    match read_result {
        Ok(n) => {
            if n == 0 {
                println!("weird, no bytes read");
            }
            dump(buffer.as_slice(), buffer[0]+1); // Byte extra for total length
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