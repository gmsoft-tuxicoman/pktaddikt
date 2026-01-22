use crate::proto::ProtoParser;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;
use crate::proto::ProtoField;
 
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use std::sync::RwLock;
use lazy_static::lazy_static;


type ConntrackKeyUdp = ConntrackKeyBidir<u16>;

lazy_static! {
    static ref CT_UDP: RwLock<ConntrackTable<ConntrackKeyUdp>> = RwLock::new(ConntrackTable::new());
}

pub struct ProtoUdp<'a> {
    pub pload: &'a [u8],
    fields : Vec<(&'a str, Option<ProtoField<'a>>)>
}


impl<'a> ProtoUdp<'a> {

    pub fn new(pload: &'a [u8]) -> Self {
        ProtoUdp{
            pload : pload,
            fields : vec![
                ("sport", None),
                ("dport", None) ],
        }
    }

}

impl<'a> ProtoParser for ProtoUdp<'a> {
    fn name(&self) -> &str {
        return "udp"
    }

    fn get_fields(&self) -> &Vec<(&str, Option<ProtoField<'a>>)> {
        & self.fields
    }

    //fn process(&mut self, ct_table: &mut conntrack::ConntrackTable) -> Result<ProtoSlice, ()> {
    fn process(&mut self) -> Result<ProtoSlice, ()> {
        let sport : u16 = (self.pload[0] as u16) << 8 | (self.pload[1] as u16);
        self.fields[0].1 = Some(ProtoField::U16(sport));
        let dport : u16 = (self.pload[2] as u16) << 8 | (self.pload[3] as u16);
        self.fields[1].1 = Some(ProtoField::U16(dport));
        let len : u16 = (self.pload[4] as u16) << 8 | (self.pload[5] as u16);

        if (len > (self.pload.len() as u16)) || (len < 8) {
            return Err(());
        }


        let ct_key = ConntrackKeyUdp { a: sport, b: dport };
        let mut ct_table = CT_UDP.write().unwrap();
        ct_table.get(ct_key);


        Ok( ProtoSlice {
            number_type :ProtoNumberType::Udp,
            number: dport as u32,
            start : 8,
            end: len as usize} )

    }

    fn print<'b>(&self, _prev_layer: Option<&'b Box<dyn ProtoParser + 'b>>) {

        let sport = self.fields[0].1.unwrap().get_u16();
        let dport = self.fields[1].1.unwrap().get_u16();


        print!("UDP {} -> {}", sport, dport);

    }

}
