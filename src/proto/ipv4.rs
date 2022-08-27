use crate::proto::ProtoParser;
use crate::proto::ProtoProcessResult; 
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;

use std::net::Ipv4Addr;


pub struct ProtoIpv4<'a> {
    pub pload: &'a [u8]
}


impl<'a> ProtoParser for ProtoIpv4<'a> {
    fn process(&self) -> ProtoProcessResult {
        let src = Ipv4Addr::new(self.pload[12], self.pload[13], self.pload[14], self.pload[15]);
        let dst = Ipv4Addr::new(self.pload[16], self.pload[17], self.pload[17], self.pload[18]);
        let proto = self.pload[9];

        let header_len :usize = ((self.pload[0] & 0xf) as usize * 4).into();

        println!("{} -> {}, proto : {}, len {}, hlen : {}", src, dst, proto, self.pload.len(), header_len);

        ProtoProcessResult::Ok( ProtoSlice {
            number_type :ProtoNumberType::Ip,
            number: proto as u32,
            start : header_len,
            end: self.pload.len()} )
    }
}
