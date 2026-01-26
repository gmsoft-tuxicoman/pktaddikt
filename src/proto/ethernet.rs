use crate::proto::ProtoProcessor;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoProcessResult;
use crate::proto::ProtoSlice;
use crate::proto::ProtoField;
//use crate::conntrack;

pub struct ProtoEthernet<'a> {
    pub pload: &'a [u8],
    fields : Vec<(&'a str, Option<ProtoField<'a>>)>
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


impl<'a> ProtoEthernet<'a> {

    pub fn new(pload: &'a [u8]) -> Self {
        ProtoEthernet{
            pload : pload,
            fields : vec![
                ("src", None),
                ("dst", None),
                ("type", None) ],
        }
    }

}

impl<'a> ProtoProcessor for ProtoEthernet<'a> {


    fn name(&self) -> &str {
        return "ether"
    }

    fn process(&mut self) -> Result<ProtoProcessResult, ()> {

        if self.pload.len() < 14 {
            return Err(())
        }

        let src : &[u8] = &self.pload[..6];
        self.fields[0].1 = Some(ProtoField::Mac(src.try_into().expect("MAC too small")));
        let dst : &[u8] = &self.pload[6..12];
        self.fields[1].1 = Some(ProtoField::Mac(dst.try_into().expect("MAC too small")));

        let eth_type: u16 = (self.pload[12] as u16) << 8 | (self.pload[13] as u16);
        self.fields[2].1 = Some(ProtoField::U16(eth_type));


        Ok( ProtoProcessResult {
            next_slice: ProtoSlice {
                number_type :ProtoNumberType::Ethernet,
                number: eth_type as u32,
                start : 14,
                end: self.pload.len()},
            ct: None
        })

    }

    fn print<'b>(&self, _prev_layer: Option<&'b Box<dyn ProtoProcessor + 'b>>) {

        let src = self.fields[0].1.unwrap().get_mac();
        print_ether_addr(&src);
        print!(" > ");
        let dst = self.fields[1].1.unwrap().get_mac();
        print_ether_addr(&dst);

        let type_opt = ETHER_TYPES.into_iter().find_map(| (x,y)| { if x == self.fields[2].1.unwrap().get_u16() { Some(y) } else { None }});
        let type_str;
        match type_opt {
            Some(t) => type_str = t,
            None => type_str = "Unknown"
        }
        print!(", ethertype {} ({:#06x}), length {}: ", type_str, self.fields[2].1.unwrap().get_u16(), self.pload.len());

    }
}
