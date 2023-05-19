#![doc = include_str!("../README.md")]

use crate::implementation::{Blue, Ed2kImpl, Red, RedBlue};

/// The "official" ED2K hashing algorithm. Identical to Ed2kBlue.
pub type Ed2k = Ed2kBlue;
/// The old, "buggy" ED2K hashing algorithm. See crate docs for more details.
pub type Ed2kRed = Ed2kImpl<Red>;
/// The new, "fixed" ED2K hashing algorithm. See crate docs for more details.
pub type Ed2kBlue = Ed2kImpl<Blue>;
/// This computes the `Ed2kRed` hash concatenated with the `Ed2kBlue` hash.
/// See crate docs for more details.
pub type Ed2kRedBlue = Ed2kImpl<RedBlue>;

pub use digest;

pub mod implementation;

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! define_cases {
        ($($name:ident { $value:expr, $blue:expr, $red:expr })*) => {
            $(
                mod $name {
                    use super::*;
                    use digest::Digest;

                    mod blue {
                        use super::*;

                        #[test]
                        fn test() {
                            let hash = Ed2kBlue::digest(&$value);
                            assert_eq!(format!("{hash:x}"), $blue);
                        }
                    }
                    mod red {
                        use super::*;

                        #[test]
                        fn test() {
                            let hash = Ed2kRed::digest(&$value);
                            assert_eq!(format!("{hash:x}"), $red);
                        }
                    }
                    mod red_blue {
                        use super::*;

                        #[test]
                        fn test() {
                            let hash = Ed2kRedBlue::digest(&$value);
                            assert_eq!(format!("{hash:x}"), format!("{}{}", $red, $blue));
                        }
                    }
                }
            )*
            mod all_reset {
                use super::{Ed2kBlue, Ed2kRed, Ed2kRedBlue};
                use digest::Digest;

                #[test]
                fn blue() {
                    let mut hasher = Ed2kBlue::default();
                    $(
                        hasher.update(&$value);
                        let $name = hasher.finalize_reset();
                        assert_eq!(format!("{:x}", $name), $blue);
                    )*
                }

                #[test]
                fn red() {
                    let mut hasher = Ed2kRed::default();
                    $(
                        hasher.update(&$value);
                        let $name = hasher.finalize_reset();
                        assert_eq!(format!("{:x}", $name), $red);
                    )*
                }

                #[test]
                fn red_blue() {
                    let mut hasher = Ed2kRedBlue::default();
                    $(
                        hasher.update(&$value);
                        let $name = hasher.finalize_reset();
                        assert_eq!(format!("{:x}", $name), format!("{}{}", $red, $blue));
                    )*
                }
            }
        }
    }

    define_cases! {
        empty {
            vec![0; 0],
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        }
        sub_zeroed_chunk {
            vec![0; 412],
            "a89605d61bb80c73ead447285c05f588",
            "a89605d61bb80c73ead447285c05f588"
        }
        sub_pattern_chunk {
            vec![0x55; 412],
            "41dfbddfe5a4b05236a0d932dd445a74",
            "41dfbddfe5a4b05236a0d932dd445a74"
        }
        one_zeroed_chunk {
            vec![0; 9728000],
            "d7def262a127cd79096a108e7a9fc138",
            "fc21d9af828f92a8df64beac3357425d"
        }
        one_pattern_chunk {
            vec![0x55; 9728000],
            "4127a47867b6110f0f86f2d9845fb374",
            "49e80f377b7e4e706dbd3ecc89f39306"
        }
        super_one_zeroed_chunk {
            vec![0; 9728412],
            "9828f449478a35b909e86ba9bdbce24b",
            "9828f449478a35b909e86ba9bdbce24b"
        }
        super_one_pattern_chunk {
            vec![0x55; 9728412],
            "ac4fd3e805f05d29e3e119f0f3e61bf0",
            "ac4fd3e805f05d29e3e119f0f3e61bf0"
        }
        two_zeroed_chunks {
            vec![0; 19456000],
            "194ee9e4fa79b2ee9f8829284c466051",
            "114b21c63a74b6ca922291a11177dd5c"
        }
        two_pattern_chunks {
            vec![0x55; 19456000],
            "322b445351fab0a78970a6a083693b5a",
            "54fc1e8d35b382c0aa7e73e54297c582"
        }
        super_two_zeroed_chunks {
            vec![0; 19456412],
            "38ce731644eed021ba5c14c980fd6a32",
            "38ce731644eed021ba5c14c980fd6a32"
        }
        super_two_pattern_chunks {
            vec![0x55; 19456412],
            "0171e3f247bdd948d299a5178d9295e7",
            "0171e3f247bdd948d299a5178d9295e7"
        }
    }
}
