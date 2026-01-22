use crate::proto::ProtoParser;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;
use crate::proto::ProtoField;

use crate::conntrack::ConntrackTable;
use crate::conntrack::ConntrackKeyBidir;

use std::net::Ipv4Addr;
use std::sync::RwLock;
use lazy_static::lazy_static;



type ConntrackKeyIpv4 = ConntrackKeyBidir<u32>;

struct ConntrackIpv4 {

    packet_count: u64
}



lazy_static! {
    static ref CT_IPV4: RwLock<ConntrackTable<ConntrackKeyIpv4>> = RwLock::new(ConntrackTable::new());
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

impl<'a> ProtoParser for ProtoIpv4<'a> {

    fn name(&self) -> &str {
        return "ip"
    }

    fn get_fields(&self) -> &Vec<(&str, Option<ProtoField<'a>>)> {
        & self.fields
    }

    fn process(&mut self) -> Result<ProtoSlice, ()> {
        let src = Ipv4Addr::new(self.pload[12], self.pload[13], self.pload[14], self.pload[15]);
        self.fields[0].1 = Some(ProtoField::Ipv4(src));
        let dst = Ipv4Addr::new(self.pload[16], self.pload[17], self.pload[18], self.pload[19]);
        self.fields[1].1 = Some(ProtoField::Ipv4(dst));
        let proto = self.pload[9];
        self.fields[2].1 = Some(ProtoField::U8(proto));

        let header_len = (self.pload[0] & 0xf) as u16 * 4;
        self.fields[3].1 = Some(ProtoField::U16(header_len));


        let ct_key = ConntrackKeyIpv4 { a: src.to_bits(), b: dst.to_bits()};
        let mut ct_table = CT_IPV4.write().unwrap();
        ct_table.get(ct_key);


        Ok( ProtoSlice {
            number_type :ProtoNumberType::Ip,
            number: proto as u32,
            start : header_len as usize,
            end: self.pload.len()} )
    }

    fn print<'b>(&self, _prev_layer: Option<&'b Box<dyn ProtoParser + 'b>>) {

        let src = self.fields[0].1.unwrap().get_ipv4();
        let dst = self.fields[1].1.unwrap().get_ipv4();
        let proto = self.fields[2].1.unwrap().get_u8();
        let ihl = self.fields[3].1.unwrap().get_u16();

        print!("{} -> {}, proto : {}, len {}, hlen : {} ", src, dst, proto, self.pload.len(), ihl);
    }
}
