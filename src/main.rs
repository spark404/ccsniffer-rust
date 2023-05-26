use crate::pcaptap::TapBlock;
use crate::sniffer::{CmdCodes, SnifferDevice, SnifferError};
use clap::Parser;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption};
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
use pcap_file::DataLink;
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::borrow::Cow;
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use std::{error::Error, thread};

mod pcaptap;
mod sniffer;

const VENDOR: u16 = 0x0451; // Texas Instruments
const PRODUCT: u16 = 0x16a8; // CC2531 USB Stick

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_parser= clap::value_parser!(u8).range(11..27), default_value="13")]
    channel: u8,

    #[arg(short = 'f', long, default_value = "capture.pcap")]
    capture_file: Option<PathBuf>,

    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let break_received = Arc::new(AtomicBool::new(false));
    let break_received_me = break_received.clone();

    println!("CCSniffer");
    println!("------------------");
    println!("  Channel: {}", cli.channel);
    if cli.capture_file.is_some() {
        let filename = cli.capture_file.as_ref().unwrap().to_str().unwrap();
        println!("  Capture file: {}", filename)
    }
    println!();

    let mut signals = Signals::new(&[SIGINT])?;
    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received signal {:?}", sig);
            if sig == 2 {
                // CTRLC
                if break_received.load(Ordering::Relaxed) {
                    // Received twice, just die
                    std::process::exit(2);
                } else {
                    println!("Attempting to stop sniffer");
                    break_received.store(true, Ordering::Relaxed);
                }
            }
        }
    });

    let file = File::create(cli.capture_file.unwrap()).expect("Error creating file");

    let device = match SnifferDevice::find_device(VENDOR, PRODUCT) {
        Some(n) => n,
        None => {
            println!("No suitable devices found.");
            exit(1);
        }
    };

    let mut sniffer = match SnifferDevice::new(device) {
        Ok(n) => n,
        Err(e) => {
            println!("Failed to open sniffer device for communication: {}", e);
            exit(1);
        }
    };

    if cli.debug {
        sniffer.set_debug();
    }

    let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();

    let idb = InterfaceDescriptionBlock {
        linktype: DataLink::IEEE802_15_4_TAP,
        snaplen: 256,
        options: vec![
            InterfaceDescriptionOption::IfName(Cow::from("cc2531-usb")),
            InterfaceDescriptionOption::IfDescription(Cow::from(sniffer.get_product_name().unwrap())),
            InterfaceDescriptionOption::IfTsResol(9), // pcap-file library uses nanoseconds for timestamps
        ],
    };
    pcap_ng_writer.write_block(&idb.into_block()).unwrap();

    let sniffer = sniffer;

    println!("Connected to {}", sniffer.get_product_name().unwrap());

    // After repeated used there might be packets in the queue
    // Drain by reading and ignoring errors
    _ = sniffer.receive_packet();

    println!("Send CmdInit");
    sniffer.send_command(sniffer::CmdCodes::CmdInit, &[])?;

    println!("Send CmdSetChannel {}", cli.channel);
    sniffer.send_command(CmdCodes::CmdSetChannel, vec![cli.channel].as_slice())?;

    println!("Send CmdSniffOn");
    sniffer.send_command(CmdCodes::CmdSniffOn, &[])?;

    println!("Looping over received packets");
    let mut received_packets = 0;

    loop {
        if break_received_me.load(Ordering::Relaxed) {
            // Stop sniffing
            break;
        }

        match sniffer.receive_packet() {
            Ok(n) => {
                let duration_since_epoch =
                    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(dt) => dt,
                        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
                    };



                // First two bytes are RSSI (dbm) and link quality index
                let mut packet_data = n.to_vec();
                let metadata: Vec<u8> = packet_data.drain(..2).collect();
                let rssi = i8::from_le_bytes([metadata[0]]) as f32;
                let lqi = metadata[1];

                let mut epd_data: Vec<u8> = vec![];

                // TAP
                TapBlock::Header(3).write_to(&mut epd_data)?;
                TapBlock::TlvRssi(rssi).write_to(&mut epd_data)?;
                TapBlock::ChannelAssignment(cli.channel as u16).write_to(&mut epd_data)?;
                TapBlock::TlvLqi(lqi).write_to(&mut epd_data)?;

                epd_data.append(&mut packet_data);

                let packet = EnhancedPacketBlock {
                    interface_id: 0,
                    timestamp: duration_since_epoch,
                    original_len: epd_data.len() as u32,
                    data: Cow::from(epd_data.as_slice()),
                    options: vec![],
                };

                pcap_ng_writer.write_block(&packet.into_block()).unwrap();
                received_packets += 1;
            }
            Err(e) => match e {
                SnifferError::TimeOut => {}
                _ => {
                    println!("read failed with error: {e}");
                    break;
                }
            },
        };
    }

    println!("Send CmdSniffOff");
    sniffer.send_command(CmdCodes::CmdSniffOff, &[])?;

    println!("Captured {} packets", received_packets);
    return Ok(());
}
