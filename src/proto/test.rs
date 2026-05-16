#![allow(unused)]

use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols};
use crate::stream::{PktStreamProcessor, PktStreamParser};
use crate::packet::{Packet, PktTime, PktInfoStack};
use crate::conntrack::ConntrackDirection;
use std::cell::RefCell;
use std::ops::Range;

#[derive(Debug)]
pub struct ProtoTest {
    expectations: Vec<ProtoTestExpect>,
}

#[derive(Debug)]
struct ProtoTestExpect {

    ts: PktTime,
    data: Vec<u8>
}

#[cfg(not(test))]
impl ProtoPktProcessor for ProtoTest {

    fn new() -> Self {
        Self {
            expectations: Vec::new(),
        }
    }

    fn process(&mut self, pkt: &mut Packet, _: &mut PktInfoStack) -> Result<(), ParseErr> {
        Err(ParseErr::Invalid("Cannot use Proto Test outside of testing"))
    }
}

#[cfg(test)]
impl ProtoPktProcessor for ProtoTest {

    fn new() -> Self {
        Self {
            expectations: Vec::new(),
        }
    }

    fn process(&mut self, pkt: &mut Packet, _: &mut PktInfoStack) -> Result<(), ParseErr> {

        let test_data = pkt.remaining_data();
        println!("Remaining data: {:x?} (len {})", test_data, test_data.len());

        let expect_pkt = self.expectations.remove(0);

        assert_eq!(expect_pkt.data, test_data);
        assert_eq!(expect_pkt.ts, pkt.timestamp());

        return Err(ParseErr::Stop);
    }
}

impl PktStreamProcessor for ProtoTest {

    fn new(infos: &PktInfoStack) -> Self {
        Self {
            expectations: Vec::new(),
        }
    }


    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {
        let data = parser.peek(0)?;
        println!("Data: {:x?}, (len: {})", data, data.len());

        let expect_pkt = self.expectations.remove(0);

        assert_eq!(expect_pkt.data, data.as_ref());

        parser.skip(data.len())?;
        assert_eq!(expect_pkt.ts, parser.timestamp());

        Ok(())
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
