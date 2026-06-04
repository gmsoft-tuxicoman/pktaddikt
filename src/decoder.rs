
use crate::decoder::gzip::DecoderGzip;

pub mod gzip;


#[derive(Debug)]
pub enum DecoderKind {
    Gzip,
    Deflate,
}

impl DecoderKind {

    pub fn from_str(name: &str) -> Option<DecoderKind> {
        match name {
            "gzip" => Some(DecoderKind::Gzip),
            "x-gzip" => Some(DecoderKind::Gzip),
            "deflate" => Some(DecoderKind::Deflate),
            _ => None,
        }
    }


}

#[derive(Debug)]
pub enum Decoder {
    Gzip(DecoderGzip), // Handles both gzip and deflate
}
