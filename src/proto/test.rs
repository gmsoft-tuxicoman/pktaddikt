#![allow(unused)]

use crate::proto::{ProtoPktProcessor, ProtoParseResult, Protocols};
use crate::stream::ProtoStreamProcessor;
use crate::packet::{Packet, PktData, PktDataOwned, PktTime};
use crate::param::Param;
use crate::conntrack::ConntrackDirection;
use std::cell::RefCell;
use std::ops::Range;

pub struct ProtoTest {}

struct ProtoTestExpect {

    ts: PktTime,
    data: Vec<u8>
}

thread_local! {
    static TEST_EXPECT: RefCell<Vec<ProtoTestExpect>> = RefCell::new(Vec::new());
}

#[cfg(not(test))]
impl ProtoPktProcessor for ProtoTest {

    fn process(pkt: &mut Packet) -> ProtoParseResult {
        return ProtoParseResult::Invalid;
    }

    fn purge() {}

}

#[cfg(test)]
impl ProtoPktProcessor for ProtoTest {

    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let test_data = pkt.remaining_data();
        println!("Remaining data: {:x?} (len {})", test_data, test_data.len());

        let expect_pkt = TEST_EXPECT.with(|expect| {
            expect.borrow_mut().remove(0)
        });

        assert_eq!(expect_pkt.data, test_data);
        assert_eq!(expect_pkt.ts, pkt.ts);

        return ProtoParseResult::Stop;
    }
    

    fn purge() {}

}

#[cfg(test)]
impl ProtoStreamProcessor for ProtoTest {

    fn new<'a>(parent_proto: Protocols, metadata: &Vec<Param<'a>>) -> Self {
        ProtoTest{}
    }


    fn process(&self,  dir: ConntrackDirection, pkt: PktDataOwned, range: Range<usize>, ts: PktTime) {
        println!("Data: {:x?}, (len: {})", pkt.data(), range.len());

        let expect_pkt = TEST_EXPECT.with(|expect| {
            expect.borrow_mut().remove(0)
        });

        assert_eq!(expect_pkt.data, pkt.data()[range]);
        assert_eq!(expect_pkt.ts, ts);
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

