use crate::packet::{Packet, PktInfoStack};
use crate::proto::Protocols;
use crate::conntrack::ConntrackDirection;
use crate::proto::test::ProtoTest;

pub trait PktStreamProcessor {
    fn new(infos: &PktInfoStack) -> Self;
    fn process(&self, dir: ConntrackDirection, pkt: &mut Packet);

}

pub enum PktStreamProto {
    Test(ProtoTest)
}

pub struct PktStream {

    proto: PktStreamProto

}

impl PktStream {

    pub fn new(proto: Protocols, infos: &PktInfoStack) -> PktStream {
        PktStream {
            proto: match proto {
                Protocols::Test => PktStreamProto::Test(ProtoTest::new(infos)),
                _ => panic!("Unsupported protocol"),
            }
        }
    }

    pub fn process_packet(&self, dir: ConntrackDirection, pkt: &mut Packet) {
        match &self.proto {
            PktStreamProto::Test(p) => p.process(dir, pkt)
        }
    }

}
