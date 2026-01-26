use crate::proto::ProtoProcessor;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;
use crate::proto::ProtoField;
use crate::proto::ProtoProcessResult;

use crate::conntrack::ConntrackTable;
use crate::conntrack::ConntrackKeyBidir;


use std::sync::Arc;
use std::sync::OnceLock;
use std::net::Ipv4Addr;



type ConntrackKeyIpv4 = ConntrackKeyBidir<u32>;

struct ConntrackIpv4 {

    packet_count: u64
}


static CT_IPV4_SIZE :usize = 65535;
static CT_IPV4: OnceLock<ConntrackTable<ConntrackKeyIpv4>> = OnceLock::new();

fn ct_ipv4() -> &'static ConntrackTable<ConntrackKeyIpv4> {
    CT_IPV4.get_or_init(|| ConntrackTable::new(CT_IPV4_SIZE))
}

pub struct ProtoIpv4<'a> {
    pub pload: &'a [u8],
    fields : Vec<(&'a str, Option<ProtoField<'a>>)>,
}



impl<'a> ProtoIpv4<'a> {

    pub fn new(pload: &'a [u8]) -> Self {
        ProtoIpv4{
            pload : pload,
            fields : vec![
                ("src", None),
                ("dst", None),
                ("proto", None),
                ("ihl", None)],
        }
    }

}

impl<'a> ProtoProcessor for ProtoIpv4<'a> {


    fn process(&mut self) -> Result<ProtoProcessResult, ()> {

        let plen = self.pload.len();
        if plen < 20 { // length smaller than IP header
            return Err(());
        }

        if self.pload[0] >> 4 != 4 { // not IP version 4
            return Err(());
        }

        let header_len = (self.pload[0] & 0xf) as u16 * 4;
        self.fields[3].1 = Some(ProtoField::U16(header_len));

        if header_len < 20 { // header length smaller than minimum IP header
            return Err(());
        }

        let tot_len :u16 = (self.pload[2] as u16) << 8 | self.pload[3] as u16;
        if tot_len < header_len { // datagram size < header length
            return Err(());
        } else if (tot_len as usize) > plen { // Truncated packet
            return Err(());
        }


        let src = Ipv4Addr::new(self.pload[12], self.pload[13], self.pload[14], self.pload[15]);
        self.fields[0].1 = Some(ProtoField::Ipv4(src));
        let dst = Ipv4Addr::new(self.pload[16], self.pload[17], self.pload[18], self.pload[19]);
        self.fields[1].1 = Some(ProtoField::Ipv4(dst));
        let proto = self.pload[9];
        self.fields[2].1 = Some(ProtoField::U8(proto));

        let header_len = (self.pload[0] & 0xf) as u16 * 4;
        self.fields[3].1 = Some(ProtoField::U16(header_len));


        let ct_key = ConntrackKeyIpv4 { a: src.to_bits(), b: dst.to_bits()};
        let ct = ct_ipv4().get(ct_key);


        Ok( ProtoProcessResult {
            next_slice: ProtoSlice {
                number_type :ProtoNumberType::Ip,
                number: proto as u32,
                start : header_len as usize,
                end: self.pload.len()},
            ct: Some(Arc::downgrade(&ct))
        })

    }

    fn print<'b>(&self, _prev_layer: Option<&'b Box<dyn ProtoProcessor + 'b>>) {

        let src = self.fields[0].1.unwrap().get_ipv4();
        let dst = self.fields[1].1.unwrap().get_ipv4();
        let proto = self.fields[2].1.unwrap().get_u8();
        let ihl = self.fields[3].1.unwrap().get_u16();

        print!("{} -> {}, proto : {}, len {}, hlen : {} ", src, dst, proto, self.pload.len(), ihl);
    }
}
