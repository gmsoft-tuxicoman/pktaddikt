use crate::proto::{ProtoProcessor, ProtoParseResult};
use crate::packet::{Packet, PktTime};
use std::cell::RefCell;

pub struct ProtoTest {}


struct ProtoTestExpect {

    ts: PktTime,
    data: Vec<u8>
}

thread_local! {
    static TEST_EXPECT: RefCell<Vec<ProtoTestExpect>> = RefCell::new(Vec::new());

}

#[cfg(not(test))]
impl ProtoProcessor for ProtoTest {

    fn process(pkt: &mut Packet) -> ProtoParseResult {
        return ProtoParseResult::Invalid;
    }

    fn purge() {}

}

#[cfg(test)]
impl ProtoProcessor for ProtoTest {

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
impl ProtoTest {

    pub fn add_expectation(data: &[u8], ts: PktTime) {

        TEST_EXPECT.with(|expect| {
           expect.borrow_mut().push(ProtoTestExpect {
               ts: ts,
               data: data.to_vec(),
           });
        });
    }
}
