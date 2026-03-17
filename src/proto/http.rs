
use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult};
use crate::packet::PktInfoStack;
use crate::conntrack::ConntrackDirection;

use tracing::trace;


pub struct ProtoHttp {

}


impl PktStreamProcessor for ProtoHttp {

    fn new(infos: &PktInfoStack) -> Self {
        ProtoHttp {}
    }

    fn process(&self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        let line = parser.readline();
        if line.is_none() {
            return StreamParseResult::NeedData;
        }

        trace!("HTTP LINE ! {}", String::from_utf8_lossy(line.as_ref().unwrap()));
        return StreamParseResult::Ok;
    }

}
