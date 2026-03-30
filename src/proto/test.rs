#![allow(unused)]

use crate::proto::{ProtoPktProcessor, ProtoParseResult, Protocols};
use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult};
use crate::packet::{Packet, PktData, PktDataOwned, PktTime, PktInfoStack};
use crate::param::Param;
use crate::conntrack::ConntrackDirection;
use std::cell::RefCell;
use std::ops::Range;

pub struct ProtoTest {}

impl ProtoTest {
    pub fn new() -> Self {
        Self {}
    }
}

struct ProtoTestExpect {

    ts: PktTime,
    data: Vec<u8>
}

thread_local! {
    static TEST_EXPECT: RefCell<Vec<ProtoTestExpect>> = RefCell::new(Vec::new());
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

        let expect_pkt = TEST_EXPECT.with(|expect| {
            expect.borrow_mut().remove(0)
        });

        assert_eq!(expect_pkt.data, test_data);
        assert_eq!(expect_pkt.ts, pkt.ts);

        return ProtoParseResult::Stop;
    }
}

impl PktStreamProcessor for ProtoTest {

    fn new(infos: &PktInfoStack) -> Self {
        ProtoTest{}
    }


    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        let data = parser.remaining_data();
        println!("Data: {:x?}, (len: {})", data, data.len());

        let expect_pkt = TEST_EXPECT.with(|expect| {
            expect.borrow_mut().remove(0)
        });

        assert_eq!(expect_pkt.data, data.as_ref());
        assert_eq!(expect_pkt.ts, parser.timestamp());

        return StreamParseResult::Ok;
    }

}

#[cfg(test)]
impl ProtoTest {

    pub fn add_expectation(data: &[u8], ts: PktTime) {

        TEST_EXPECT.with(|expect| {
           expect.borrow_mut().push(ProtoTestExpect {
               ts: ts,
               data: data.to_vec(),
           });
        });
    }

    pub fn assert_empty() {
        TEST_EXPECT.with(|expect| {
            assert_eq!(expect.borrow().len(), 0, "Some packets are still expected");
        });
    }
}

