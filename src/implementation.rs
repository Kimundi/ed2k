use digest::{
    generic_array::{ArrayLength, GenericArray},
    typenum::{U16, U32},
    FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update,
};
use md4::Md4;

const CHUNK_SIZE: usize = 9728000;
type Array<T> = GenericArray<u8, T>;

#[derive(Default, Debug, Clone)]
struct ChunkHasher(Md4);
impl ChunkHasher {
    fn digest_reset(&mut self, data: &[u8]) -> Array<U16> {
        self.0.update(data);
        self.0.finalize_fixed_reset()
    }
}

#[derive(Default, Debug, Clone)]
struct ChunkList {
    hasher: Md4,
    first_chunk: Array<U16>,
    chunk_counter: u64,
}
impl ChunkList {
    fn add_chunk(&mut self, hash: &Array<U16>) {
        if self.chunk_counter == 0 {
            self.first_chunk.copy_from_slice(hash);
        }
        self.chunk_counter += 1;
        self.hasher.update(hash);
    }
    fn reset(&mut self) {
        self.hasher.reset();
        self.chunk_counter = 0;
        self.first_chunk.fill(0);
    }
    fn chunk_counter(&self) -> u64 {
        self.chunk_counter
    }
    fn copy_first_chunk(&self, out: &mut Array<U16>) {
        debug_assert!(self.chunk_counter > 0);
        out.copy_from_slice(&self.first_chunk);
    }
    fn copy_list_hash_reset(&mut self, out: &mut Array<U16>) {
        self.hasher.finalize_into_reset(out);
    }
}

pub trait Ed2kColor: Sized + Default {
    type OutputSize: ArrayLength<u8> + 'static;
    fn finalize_ref(state: &mut Ed2kState, out: &mut Array<Self::OutputSize>);
}

#[derive(Default, Debug)]
pub struct Red;

#[derive(Default, Debug)]
pub struct Blue;

#[derive(Default, Debug)]
pub struct RedBlue;

#[derive(Debug, Clone)]
pub struct Ed2kState {
    chunk_hasher: ChunkHasher,
    chunk: Vec<u8>,
    chunk_list: ChunkList,
}

#[derive(Debug, Clone)]
pub struct Ed2kImpl<C> {
    state: Ed2kState,
    _color: C,
}

impl<C> Default for Ed2kImpl<C>
where
    C: Ed2kColor,
{
    fn default() -> Self {
        Self {
            state: Ed2kState {
                chunk_hasher: Default::default(),
                chunk: Vec::with_capacity(CHUNK_SIZE),
                chunk_list: Default::default(),
            },
            _color: Default::default(),
        }
    }
}

impl<C> Update for Ed2kImpl<C>
where
    C: Ed2kColor,
{
    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let free = CHUNK_SIZE - self.state.chunk.len();
            let data_write_len = data.len().min(free);
            let data_write;
            (data_write, data) = data.split_at(data_write_len);
            self.state.chunk.extend(data_write);
            if self.state.chunk.len() == CHUNK_SIZE {
                self.state.hash_chunk();
            }
        }
    }
}

impl Ed2kState {
    fn hash_chunk(&mut self) {
        let hash = self.chunk_hasher.digest_reset(&self.chunk);
        self.chunk_list.add_chunk(&hash);
        self.chunk.clear();
    }
}

impl<C> FixedOutput for Ed2kImpl<C>
where
    C: Ed2kColor,
{
    fn finalize_into(mut self, out: &mut Array<Self::OutputSize>) {
        C::finalize_ref(&mut self.state, out)
    }
}

impl<C> OutputSizeUser for Ed2kImpl<C>
where
    C: Ed2kColor,
{
    type OutputSize = C::OutputSize;
}

impl<C> HashMarker for Ed2kImpl<C> where C: Ed2kColor {}

impl<C> Reset for Ed2kImpl<C>
where
    C: Ed2kColor,
{
    fn reset(&mut self) {
        self.state.chunk.clear();
        self.state.chunk_list.reset();
    }
}

impl<C> FixedOutputReset for Ed2kImpl<C>
where
    C: Ed2kColor,
{
    fn finalize_into_reset(&mut self, out: &mut Array<Self::OutputSize>) {
        C::finalize_ref(&mut self.state, out);
        self.reset();
    }
}

impl Ed2kColor for Red {
    type OutputSize = U16;
    fn finalize_ref(state: &mut Ed2kState, out: &mut Array<U16>) {
        // simple case: input data was less than a chunk.
        // state: |##> |
        if state.chunk_list.chunk_counter() == 0 {
            state.hash_chunk();
            state.chunk_list.copy_first_chunk(out);
            return;
        }

        // otherwise there are two cases:
        // - Input ends between two chunk boundaries.
        //   The remaining data in the current chunk still needs to be hashed.
        //   state: |####|..|##> |
        // - Input ends on a chunk boundary. We have already hashed all data,
        //   but we need to add an hash of the empty byte sequence to
        //   produce the right output. `state.chunk` is empty in this case,
        //   so we can just use it.
        //   state: |####|..|> |
        state.hash_chunk();
        state.chunk_list.copy_list_hash_reset(out);
    }
}

impl Ed2kColor for Blue {
    type OutputSize = U16;
    fn finalize_ref(state: &mut Ed2kState, out: &mut Array<U16>) {
        // simple case: input data was less than a chunk.
        // state: |##> |
        if state.chunk_list.chunk_counter() == 0 {
            state.hash_chunk();
            state.chunk_list.copy_first_chunk(out);
            return;
        }

        // common case: input data was more than a chunk, and
        // ends between two chunk boundaries.
        // state: |####|..|##> |
        if !state.chunk.is_empty() {
            state.hash_chunk();
            state.chunk_list.copy_list_hash_reset(out);
            return;
        }

        // rare case: input data is a multiple of the chunk size
        // state: |####|..|>   |
        if state.chunk_list.chunk_counter() == 1 {
            state.chunk_list.copy_first_chunk(out);
        } else {
            state.chunk_list.copy_list_hash_reset(out);
        }
    }
}

impl Ed2kColor for RedBlue {
    type OutputSize = U32;
    fn finalize_ref(state: &mut Ed2kState, out: &mut Array<U32>) {
        // split the output array into two parts
        let (red_out, blue_out) = out.split_at_mut(16);
        let red_out = Array::<U16>::from_mut_slice(red_out);
        let blue_out = Array::<U16>::from_mut_slice(blue_out);

        // simple case: input data was less than a chunk.
        // state: |##> |
        if state.chunk_list.chunk_counter() == 0 {
            state.hash_chunk();
            state.chunk_list.copy_first_chunk(red_out);
            blue_out.copy_from_slice(&red_out[..]);
            return;
        }

        // common case: input data was more than a chunk, and
        // ends between two chunk boundaries.
        // state: |####|..|##> |
        if !state.chunk.is_empty() {
            state.hash_chunk();
            state.chunk_list.copy_list_hash_reset(red_out);
            blue_out.copy_from_slice(&red_out[..]);
            return;
        }

        // rare case: input data is a multiple of the chunk size
        // state: |####|..|>   |

        // for blue, we want to produce a hash only based on the
        // chunk list
        if state.chunk_list.chunk_counter() == 1 {
            state.chunk_list.copy_first_chunk(blue_out);
        } else {
            // we need to keep the list state for red below,
            // so we work on a cheap clone here.
            state.chunk_list.clone().copy_list_hash_reset(blue_out);
        }

        // for red, we have to add an hash of the empty byte sequence
        // to the chunk list. `state.chunk` is empty at this point, so
        // we can just hash it.
        state.hash_chunk();
        state.chunk_list.copy_list_hash_reset(red_out);
    }
}
