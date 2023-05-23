use crate::sniffer::{CmdCodes, SnifferDevice};
use clap::Parser;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
use pcap_file::DataLink;
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::borrow::Cow;
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{error::Error, thread, time::Duration};
use std::time::SystemTime;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption::IfTsResol;

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
    let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();

    let device = match SnifferDevice::find_device(VENDOR, PRODUCT) {
        Some(n) => n,
        None => {
            println!("No suitable devices found.");
            exit(1);
        }
    };

    let sniffer = match SnifferDevice::new(device) {
        Ok(n) => n,
        Err(e) => {
            println!("Failed to open sniffer device for communication: {}", e);
            exit(1);
        }
    };

    println!("Connected to {}", sniffer.get_product_name().unwrap());

    println!("Send CmdInit");
    sniffer.send_command(sniffer::CmdCodes::CmdInit, &[]);

    println!("Send CmdSetChannel {}", cli.channel);
    sniffer.send_command(CmdCodes::CmdSetChannel, vec![cli.channel].as_slice());

    println!("Send CmdSniffOn");
    sniffer.send_command(CmdCodes::CmdSniffOn, &[]);

    println!("Looping over received packets");
    let mut received_packets = 0;

    loop {
        if break_received_me.load(Ordering::Relaxed) {
            // Stop sniffing
            break;
        }

        match sniffer.receive_packet() {
            Ok(n) => {
                let duration_since_epoch = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(dt) => dt,
                    Err(_) => panic!("SystemTime before UNIX EPOCH!"),
                };

                let idb = InterfaceDescriptionBlock {
                    linktype: DataLink::IEEE802_15_4_NOFCS,
                    snaplen: 0,
                    options: vec![
                        IfTsResol(9)  // pcap-file library uses nanoseconds for timestamps
                    ],
                };

                // For TAP add the following
                // TAP header 32 bits
                // let mut epd_data: Vec<u8> = vec![];
                // epd_data.push(0);
                // epd_data.push(0);
                // epd_data.push(0);
                // epd_data.push(0);

                let packet = EnhancedPacketBlock {
                    interface_id: 0,
                    timestamp: duration_since_epoch,
                    original_len: n.len() as u32,
                    data: Cow::from(n.as_slice()),
                    options: vec![],
                };

                pcap_ng_writer.write_block(&idb.into_block()).unwrap();
                pcap_ng_writer.write_block(&packet.into_block()).unwrap();
                received_packets += 1;
            },
            Err(e) => {
                println!("read failed: {e}");
            }
        };
    }


    println!("Send CmdSniffOff");
    sniffer.send_command(CmdCodes::CmdSniffOff, &[]);

    println!("Captured {} packets", received_packets);
    return Ok(());
}
