use crate::base::{Parser, ParseErr};

#[inline]
pub fn read_opaque<T: Parser>(parser: &mut T) -> Result<Vec<u8>, ParseErr> {

    let len = parser.read_u32_be()?;
    let ret = parser.read(len)?.into_owned();

    let align = (4 - (len & 3)) & 3;

    if align > 0 {
        parser.skip(align)?;
    }

    Ok(ret)
}

#[inline]
pub fn skip_opaque<T: Parser>(parser: &mut T) -> Result<(), ParseErr> {

    let mut len = parser.read_u32_be()?;

    // Align to 4 bytes
    len = (len + 3) & !3;
    parser.skip(len)

}

