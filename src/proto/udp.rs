use crate::proto::ProtoParser;
use crate::proto::ProtoProcessResult;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;
 

pub struct ProtoUdp<'a> {
    pub pload: &'a [u8]
}

impl<'a> ProtoParser for ProtoUdp<'a> {
    fn process(&self) -> ProtoProcessResult {
        let sport : u16 = (self.pload[0] as u16) << 8 | (self.pload[1] as u16);
        let dport : u16 = (self.pload[2] as u16) << 8 | (self.pload[3] as u16);
        let len : u16 = (self.pload[4] as u16) << 8 | (self.pload[5] as u16);

        println!("UDP {} -> {}", sport, dport);

        ProtoProcessResult::Ok( ProtoSlice {
            number_type :ProtoNumberType::Udp,
            number: dport as u32,
            start : 8,
            end: self.pload.len()} )

    }

}
