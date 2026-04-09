use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use serde::Serialize;
use std::fmt;


pub struct Param {
    pub name: &'static str,
    pub value: Option<ParamValue>
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ParamValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Mac([u8;6]),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr)
}

impl ParamValue {

    pub fn get_u8(&self) -> u8 {
        match self {
            ParamValue::U8(val) => *val,
            _ => panic!("Trying to fetch u8")
        }
    }
    pub fn get_u16(&self) -> u16 {
        match self {
            ParamValue::U16(val) => *val,
            _ => panic!("Trying to fetch u16")
        }
    }
    pub fn get_u32(&self) -> u32 {
        match self {
            ParamValue::U32(val) => *val,
            _ => panic!("Trying to fetch u32")
        }
    }
    pub fn get_u64(&self) -> u64 {
        match self {
            ParamValue::U64(val) => *val,
            _ => panic!("Trying to fetch u64")
        }
    }
    pub fn get_mac(&self) -> [u8;6] {
        match self {
            ParamValue::Mac(val) => *val,
            _ => panic!("Trying to fetch mac address")
        }
    }
    pub fn get_ipv4(&self) -> Ipv4Addr {
        match self {
            ParamValue::Ipv4(val) => *val,
            _ => panic!("Trying to fetch ipv4")
        }
    }
    pub fn get_ipv6(&self) -> Ipv6Addr {
        match self {
            ParamValue::Ipv6(val) => *val,
            _ => panic!("Trying to fetch ipv6")
        }
    }

}

impl fmt::Display for ParamValue {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamValue::U8(v) => write!(f, "{}", v),
            ParamValue::U16(v) => write!(f, "{}", v),
            ParamValue::U32(v) => write!(f, "{}", v),
            ParamValue::U64(v) => write!(f, "{}", v),
            ParamValue::Mac(v) => write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", v[0], v[1], v[2], v[3], v[4], v[5]),
            ParamValue::Ipv4(v) => write!(f, "{}", v),
            ParamValue::Ipv6(v) => write!(f, "{}", v),
        }
    }


}

#[cfg(test)]
pub mod tests {

    use super::*;

    pub fn param_assert_eq(param: &Param, name: &str, value: ParamValue) {
        assert_eq!(param.name, name, "Param name {} does not match {}", param.name, name);
        assert_eq!(param.value.unwrap(), value, "Param value {:?} does not match {:?}", param.value, value);
    }


}
