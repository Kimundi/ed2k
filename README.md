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
