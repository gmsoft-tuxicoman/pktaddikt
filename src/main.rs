extern crate getopts;
use getopts::Options;
use pcap::{Capture, Linktype};
use std::env;

use crate::packet::{Packet, PktTime, PktDataSimple};
use crate::proto::{Proto, Protocols};

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub mod proto;
pub mod conntrack;
pub mod param;
pub mod packet;
pub mod timer;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}


fn main() {


    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("r", "read", "input PCAP file", "NAME");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]){
        Ok(m) => { m }
        Err(f) => { panic!("{}", f.to_string()) }
    };


    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }


    let subscriber = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env());

    tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global subscriber");


    let filename = match matches.opt_str("r") {
        None => { panic!("No filename provided") }
        Some(f) => { f }
    };

    let mut cap = Capture::from_file(filename).unwrap();


    let datalink = cap.get_datalink();
    println!("Capture datalink : {:?}", datalink);

    // We only handle ethernet for now
    assert_eq!(datalink, Linktype::ETHERNET);

    while let Ok(pcap_pkt) = cap.next_packet() {

        let ts: PktTime = (pcap_pkt.header.ts.tv_sec as u64 * 1000000) + pcap_pkt.header.ts.tv_usec as u64;
        let mut pkt_data = PktDataSimple::new(pcap_pkt.data);

        let mut pkt = Packet::new(ts, Protocols::Ethernet, &mut pkt_data);



        Proto::process_packet(&mut pkt);
    }

    Proto::purge_all();

}


