use crate::CmdCodes::{CmdInit, CmdInitAck, CmdSetChannel, CmdSetChannelAck};
use crc::{Crc, CRC_16_XMODEM};
use rusb::DeviceList;
use rusb::Direction::{In, Out};
use std::process::exit;
use std::time::Duration;
use hxdmp::hexdump;

pub const CRC_16: Crc<u16> = Crc::<u16>::new(&CRC_16_XMODEM);

#[repr(u8)]
#[derive(PartialEq, PartialOrd)]
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

fn main() {
    println!("CCSniffer");

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

    println!("Send CmdInit");
    let mut out_buffer: Vec<u8> = vec![0; 256];
    out_buffer[0] = 3; // length
    out_buffer[1] = CmdInit as u8; // command
    out_buffer[2] = calculate_crc(out_buffer.as_slice(), 2); //checksum
    let _write_result = sniffer.write_bulk(
        out_endpoint.address(),
        &out_buffer[0..3],
        Duration::from_millis(250),
    );
    dump(&out_buffer, out_buffer[0]);

    let mut in_buffer: Vec<u8> = vec![0; 256];
    let read_result = sniffer.read_bulk(
        in_endpoint.address(),
        in_buffer.as_mut_slice(),
        Duration::from_millis(250),
    );
    match read_result {
        Ok(n) => {
            if n == 0 {
                println!("weird, no bytes read");
                return;
            }
            if in_buffer[2] != CmdInitAck as u8 {
                println!("Unexpected result {:?}", in_buffer[2]);
                dump(in_buffer.as_slice(), in_buffer[0]);
                //return;
            }
            println!("CmdInit OK")
        }
        Err(e) => {
            println!("read failed: {e}");
        }
    }

    println!("Send CmdSetChannel 15");
    out_buffer[0] = 4; // length
    out_buffer[1] = CmdSetChannel as u8; // command
    out_buffer[2] = 15; // channel
    out_buffer[3] = calculate_crc(out_buffer.as_slice(), 3); //checksum
    let _write_result = sniffer.write_bulk(
        out_endpoint.address(),
        &out_buffer[0..4],
        Duration::from_millis(250),
    );
    dump(&out_buffer, out_buffer[0]);

    let mut in_buffer: Vec<u8> = vec![0; 256];
    let read_result = sniffer.read_bulk(
        in_endpoint.address(),
        in_buffer.as_mut_slice(),
        Duration::from_millis(250),
    );
    match read_result {
        Ok(n) => {
            if n == 0 {
                println!("weird, no bytes read");
            }
            if in_buffer[2] != CmdSetChannelAck as u8 {
                println!("Unexpected result {:?}", in_buffer[2]);
                dump(in_buffer.as_slice(), in_buffer[0]);
                return;
            }
            println!("CmdSetChannel OK")
        }
        Err(e) => {
            println!("read failed: {e}");
        }
    }
    // sniffer.unconfigure()
    //     .expect("Unconfigure failed");
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