#![allow(unused)]

use crate::proto::{ProtoPktProcessor, ProtoParseResult, Protocols};
use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult};
use crate::packet::{Packet, PktData, PktDataOwned, PktTime, PktInfoStack};
use crate::param::Param;
use crate::conntrack::ConntrackDirection;
use std::cell::RefCell;
use std::ops::Range;

pub struct ProtoTest {
    expectations: Vec<ProtoTestExpect>,
}

impl ProtoTest {
    pub fn new() -> Self {
        Self {
            expectations: Vec::new(),
        }
    }
}

struct ProtoTestExpect {

    ts: PktTime,
    data: Vec<u8>
}

#[cfg(not(test))]
impl ProtoPktProcessor for ProtoTest {

    fn process(&mut self, pkt: &mut Packet, _: &mut PktInfoStack) -> ProtoParseResult {
        return ProtoParseResult::Invalid;
    }
}

#[cfg(test)]
impl ProtoPktProcessor for ProtoTest {

    fn process(&mut self, pkt: &mut Packet, _: &mut PktInfoStack) -> ProtoParseResult {

        let test_data = pkt.remaining_data();
        println!("Remaining data: {:x?} (len {})", test_data, test_data.len());

        let expect_pkt = self.expectations.remove(0);

        assert_eq!(expect_pkt.data, test_data);
        assert_eq!(expect_pkt.ts, pkt.ts);

        return ProtoParseResult::Stop;
    }
}

impl PktStreamProcessor for ProtoTest {

    fn new(infos: &PktInfoStack) -> Self {
        ProtoTest::new()
    }


    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        let data = parser.remaining_data();
        println!("Data: {:x?}, (len: {})", data, data.len());

        let expect_pkt = self.expectations.remove(0);

        assert_eq!(expect_pkt.data, data.as_ref());
        assert_eq!(expect_pkt.ts, parser.timestamp());

        return StreamParseResult::Ok;
    }

}

#[cfg(test)]
impl ProtoTest {

    pub fn add_expectation(&mut self, data: &[u8], ts: PktTime) {

        self.expectations.push(ProtoTestExpect {
           ts: ts,
           data: data.to_vec(),
        });
    }

}

#[cfg(test)]
impl Drop for ProtoTest {
    fn drop(&mut self) {
        assert_eq!(self.expectations.len(), 0, "Some packets are still expected");
    }
}
