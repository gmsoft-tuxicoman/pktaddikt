use crate::proto::ProtoParser;
use crate::proto::ProtoProcessResult;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;

pub struct ProtoEthernet<'a> {
    pub pload: &'a [u8]
}

impl<'a> ProtoParser for ProtoEthernet<'a> {
    fn process(&self) -> ProtoProcessResult {

        if self.pload.len() < 14 {
            return ProtoProcessResult::Invalid
        }

        let src : &[u8] = &self.pload[..6];
        let dst : &[u8] = &self.pload[6..12];
        let eth_type: u16 = (self.pload[12] as u16) << 8 | (self.pload[13] as u16);

        println!("{:X?} -> {:X?}, type: {:x}", src, dst, eth_type);

        ProtoProcessResult::Ok( ProtoSlice {
            number_type :ProtoNumberType::Ethernet,
            number: eth_type as u32,
            start : 14,
            end: self.pload.len()} )
    }
}
