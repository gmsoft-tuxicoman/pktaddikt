use std::cmp::Ordering;
use std::ops::AddAssign;
use std::ops::Add;
use std::ops::Sub;


// Handles wrapping sequences arithmetic

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct TcpSeq(pub u32);
impl Ord for TcpSeq {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.0 == other.0 {
            return Ordering::Equal;
        } else if other.0.wrapping_sub(self.0) < ( 1 << 31) {
            return Ordering::Less;
        } else {
            return Ordering::Greater;
        }

    }
}

impl PartialOrd for TcpSeq {

    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AddAssign<u32> for TcpSeq {

    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl Add<u32> for TcpSeq {
    type Output = TcpSeq;
    
    fn add(self, rhs: u32) -> Self::Output {
        TcpSeq(self.0.wrapping_add(rhs))
    }
}

impl Sub<TcpSeq> for TcpSeq {
    type Output = TcpSeq;

    fn sub(self, rhs: TcpSeq) -> Self::Output {
        TcpSeq(self.0.wrapping_sub(rhs.0))
    }
}

impl From<TcpSeq> for u32 {

    fn from(s: TcpSeq) -> u32 {
        s.0
    }
}

impl From<TcpSeq> for usize {

    fn from(s: TcpSeq) -> usize {
        s.0 as usize
    }
}
