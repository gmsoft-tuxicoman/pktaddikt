use crate::proto::ProtoProcessor;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;
use crate::proto::ProtoProcessResult;
use crate::conntrack::ConntrackWeakRef;

use crate::param::Param;

use std::net::Ipv6Addr;


pub struct ProtoIpv6<'a> {
    pub pload: &'a [u8],
    fields : Vec<(&'a str, Option<Param<'a>>)>
}

impl<'a> ProtoIpv6<'a> {

    pub fn new(pload: &'a [u8]) -> Self {
        ProtoIpv6{
            pload : pload,
            fields : vec![
                ("src", None),
                ("dst", None),
                ("hlim", None)
            ]
        }
    }

}

impl<'a> ProtoProcessor for ProtoIpv6<'a> {

    fn process(&mut self, ce_parent: Option<ConntrackWeakRef>) -> Result<ProtoProcessResult, ()> {
        let src = Ipv6Addr::new((self.pload[8] as u16) << 8 | (self.pload[9] as u16),
                                (self.pload[10] as u16) << 8 | (self.pload[11] as u16),
                                (self.pload[12] as u16) << 8 | (self.pload[13] as u16),
                                (self.pload[14] as u16) << 8 | (self.pload[15] as u16),
                                (self.pload[16] as u16) << 8 | (self.pload[17] as u16),
                                (self.pload[18] as u16) << 8 | (self.pload[19] as u16),
                                (self.pload[20] as u16) << 8 | (self.pload[21] as u16),
                                (self.pload[22] as u16) << 8 | (self.pload[23] as u16));
        self.fields[0].1 = Some(Param::Ipv6(src));
        let dst = Ipv6Addr::new((self.pload[24] as u16) << 8 | (self.pload[25] as u16),
                                (self.pload[26] as u16) << 8 | (self.pload[27] as u16),
                                (self.pload[28] as u16) << 8 | (self.pload[29] as u16),
                                (self.pload[30] as u16) << 8 | (self.pload[31] as u16),
                                (self.pload[32] as u16) << 8 | (self.pload[33] as u16),
                                (self.pload[34] as u16) << 8 | (self.pload[35] as u16),
                                (self.pload[36] as u16) << 8 | (self.pload[37] as u16),
                                (self.pload[38] as u16) << 8 | (self.pload[39] as u16));
        self.fields[1].1 = Some(Param::Ipv6(dst));

        let hop_limit = self.pload[7];
        self.fields[2].1 = Some(Param::U8(hop_limit));

        let mut nhdr: u8 = self.pload[6];
        let mut offset: usize = 40;

        loop {
            match nhdr {
                0  |  // HOPOPTS
                43 |  // ROUTING
                44 |  // FRAGMENT (TODO)
                60 => { // DSTOPTS
                    let hdr_len: u8 = self.pload[offset + 1];
                    offset += (hdr_len as usize) + 1;
                    nhdr = self.pload[offset];
                }
                _ => {
                    break;
                }
            }

        }

        Ok( ProtoProcessResult {
            next_slice: ProtoSlice {
                number_type :ProtoNumberType::Ip,
                number: nhdr as u32,
                start : offset,
                end: self.pload.len()},
            ct: None // FIXME when adding conntrack
        })
    }

    fn print<'b>(&self, _prev_layer: Option<&'b Box<dyn ProtoProcessor + 'b>>) {

        let src = self.fields[0].1.unwrap().get_ipv6();
        let dst = self.fields[1].1.unwrap().get_ipv6();

        print!("{} -> {} ", src, dst);
    }
}
