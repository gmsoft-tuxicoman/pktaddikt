extern crate getopts;
use getopts::Options;
use pcap::Capture;
use std::env;

use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub mod proto;
pub mod conntrack;

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

    let mut p = proto::Proto;

    while let Ok(packet) = cap.next_packet() {

        p.process_packet(packet.data, datalink);
    }

}


