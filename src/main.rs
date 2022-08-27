
use pcap::{Capture,Linktype};

pub mod proto;


fn main() {


    let mut cap = Capture::from_file("tftp.cap").unwrap();


    let datalink = cap.get_datalink();
    println!("Capture datalink : {:?}", datalink);

    while let Ok(packet) = cap.next_packet() {


        process_packet(packet.data, datalink);
    }

}


fn process_packet(data: &[u8], lt: Linktype) {
    
    assert_eq!(lt, Linktype(1));

    let mut t = proto::ProtoNumberType::Pcap;
    let mut n = lt.0 as u32;
    let mut data = data;

    loop {
        let p_res = proto::get_next_proto(t, n, data);
        let p = match p_res {
            Ok(p) => p,
            _ => break,
        };
        let res =  p.process();
        match res {
            proto::ProtoProcessResult::Ok(proto_slice) => {
                    t = proto_slice.number_type;
                    n = proto_slice.number;
                    data = &data[proto_slice.start .. proto_slice.end];
            },
            _ => break 
        }
        
    }
}
