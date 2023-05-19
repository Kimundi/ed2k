# ED2K hash functions

This implements multiple flavors of the ED2K hash function as described on
<https://mldonkey.sourceforge.net/Ed2k-hash>, and verfied against
other implementations.

The Algorithm roughly works as follows:
- The data is split into 9500 KiB chunks, where the last one can be smaller.
- Each chunk is hashed with the MD4 algorithm.
- If the file is smaller than a single chunk, the result is the hash of
  the first chunk.
- Otherwise, the result is the MD4 hash of all concatenated chunk hashes.

It turned out that when the ED2K algorithm was originally released,
there was an ambiguity in its description that allowed two ways to implement it,
which caused diverging implementations in tools. The ambiguity seems to have
been resolved later on, with the alternative behavior now being regarded as a
bug and fixed in reference implementations.


This crate implements both forms, as well as an efficient way to compute both at once:

- Ed2k "Red: This is the original, "buggy" hash function. If the data is a
  multiple of the chunk size, then an extra 0-byte sized chunk will be
  included in its computation at the end.
- Ed2k "Blue": This is the newer "fixed" hash function. If the data is a
  multiple of the chunk size, then only those chunks will be
  included in its computation at the end.
- Ed2k "RedBlue": This is just the "Red" hash concatenated with the "Blue" hash.
  This exist as a convenient hack to make use of the same hashing APIs while
  efficentily computing both ED2K hash flavors at once.

# Example

```
use digest::Digest;
use ed2k::{Ed2k, Ed2kRed, Ed2kBlue};

// Compute a ED2K hash.
let hash = Ed2k::digest(b"hello world");
assert_eq!(format!("{hash:x}"), "aa010fbc1d14c795d86ef98c95479d17");

// Difference between blue and red flavors.
// The two only differ for data that ends on a chunk boundary.
let data = vec![0x55; 9728000];
let red_hash = Ed2kRed::digest(&data);
let blue_hash = Ed2kBlue::digest(&data);
assert_eq!(format!("{red_hash:x}"), "49e80f377b7e4e706dbd3ecc89f39306");
assert_eq!(format!("{blue_hash:x}"), "4127a47867b6110f0f86f2d9845fb374");
```
