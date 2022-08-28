use crate::proto::ProtoParser;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;

pub struct ProtoEthernet<'a> {
    pub pload: &'a [u8]
}

fn print_ether_addr(addr : &[u8]) {
    print!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

const ETHER_TYPES : [(u16, &str); 4] = [
  (0x0800, "IPv4"),
  (0x0806, "ARP"),
  (0x86DD, "IPv6"),
  (0x0810, "802.1Q")

];

impl<'a> ProtoParser for ProtoEthernet<'a> {
    fn name(&self) -> &str {
        return "ether"
    }
    fn process(&self) -> Result<ProtoSlice, ()> {

        if self.pload.len() < 14 {
            return Err(())
        }

        let src : &[u8] = &self.pload[..6];
        let dst : &[u8] = &self.pload[6..12];
        let eth_type: u16 = (self.pload[12] as u16) << 8 | (self.pload[13] as u16);

        print_ether_addr(src);
        print!(" > ");
        print_ether_addr(dst);
        let type_opt = ETHER_TYPES.into_iter().find_map(| (x,y)| { if x == eth_type { Some(y) } else { None }});
        let type_str;
        match type_opt {
            Some(t) => type_str = t,
            None => type_str = "Unknown"
        }
        print!(", ethertype {} ({:#06x}), length {}: ", type_str, eth_type, self.pload.len());

        Ok( ProtoSlice {
            number_type :ProtoNumberType::Ethernet,
            number: eth_type as u32,
            start : 14,
            end: self.pload.len()} )
    }
}
