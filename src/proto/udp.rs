use crate::proto::ProtoProcessor;
use crate::proto::ProtoNumberType;
use crate::proto::ProtoSlice;
use crate::proto::ProtoField;
use crate::proto::ProtoProcessResult;
 
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use std::sync::Arc;
use std::sync::OnceLock;


type ConntrackKeyUdp = ConntrackKeyBidir<u16>;


static CT_UDP_SIZE :usize = 32768;
static CT_UDP: OnceLock<ConntrackTable<ConntrackKeyUdp>> = OnceLock::new();

fn ct_udp() -> &'static ConntrackTable<ConntrackKeyUdp> {
    CT_UDP.get_or_init(|| ConntrackTable::new(CT_UDP_SIZE))
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

impl<'a> ProtoProcessor for ProtoUdp<'a> {
    fn name(&self) -> &str {
        return "udp"
    }

    fn process(&mut self) -> Result<ProtoProcessResult, ()> {
        let sport : u16 = (self.pload[0] as u16) << 8 | (self.pload[1] as u16);
        self.fields[0].1 = Some(ProtoField::U16(sport));
        let dport : u16 = (self.pload[2] as u16) << 8 | (self.pload[3] as u16);
        self.fields[1].1 = Some(ProtoField::U16(dport));
        let len : u16 = (self.pload[4] as u16) << 8 | (self.pload[5] as u16);

        if (len > (self.pload.len() as u16)) || (len < 8) {
            return Err(());
        }


        let ct_key = ConntrackKeyUdp { a: sport, b: dport };
        let ct = ct_udp().get(ct_key);


        Ok( ProtoProcessResult {
            next_slice: ProtoSlice {
                number_type :ProtoNumberType::Udp,
                number: dport as u32,
                start : 8,
                end: len as usize},
            ct: Some(Arc::downgrade(&ct))
            })

    }

    fn print<'b>(&self, _prev_layer: Option<&'b Box<dyn ProtoProcessor + 'b>>) {

        let sport = self.fields[0].1.unwrap().get_u16();
        let dport = self.fields[1].1.unwrap().get_u16();


        print!("UDP {} -> {}", sport, dport);

    }

}
