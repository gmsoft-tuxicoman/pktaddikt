use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, ProtoInfo};
use crate::packet::{Packet, PktInfoStack};


#[derive(Debug, PartialEq)]
pub struct ProtoIcmpInfo {
    r#type: u8,
    code: u8,
}

pub struct ProtoIcmp {}

impl ProtoIcmp {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProtoPktProcessor for ProtoIcmp {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {


        let icmp_type = pkt.read_u8()?;
        let icmp_code = pkt.read_u8()?;

        let info = infos.proto_last_mut();

        let proto_info = ProtoIcmpInfo {
            r#type: icmp_type,
            code: icmp_code,
        };

        info.proto_info = Some(ProtoInfo::Icmp(proto_info));

        Ok(())
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::PktTime;
    use crate::proto::Protocols;

    #[test]
    fn icmp_parse_basic() {
        let data = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        let mut infos = PktInfoStack::new(Protocols::Icmp);

        let ret = ProtoIcmp::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Ok(()));

        let info = infos.iter().next().unwrap();

        let expected = ProtoInfo::Icmp(ProtoIcmpInfo {
            r#type: 0x01,
            code: 0x02,
        });

        assert_eq!(info.proto_info, Some(expected));
    }

}
