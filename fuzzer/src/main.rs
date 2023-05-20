#[macro_use]
extern crate afl;
extern crate ed2k;

use ed2k::digest::Digest;

fn main() {
    fuzz!(|data: &[u8]| {
        ed2k::Ed2kBlue::digest(data);
        ed2k::Ed2kRed::digest(data);
        ed2k::Ed2kRedBlue::digest(data);
    });
}
