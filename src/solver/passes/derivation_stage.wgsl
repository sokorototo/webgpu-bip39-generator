// dispatch size is dynamic, through dispatch_indirect: X=*,Y=*,Z=1
const WORKGROUP_SIZE = 256; // 2 ^ 8
const P2PKH_ADDRESS_SIZE = 20;

const MAX_RESULTS_FOUND = 1398101;
const WORDS = 4;

// same as filter stage, most fields ignored
struct PushConstants {
    word0: u32,
    word1: u32,
    word3: u32,
    address: array<u32, P2PKH_ADDRESS_SIZE>,
    checksum: u32,
};

var<push_constant> constants: PushConstants;

@group(0) @binding(1)
var<storage, read> matches: array<u32, MAX_RESULTS_FOUND>;

@group(0) @binding(2) // complete list of bip39 words
var<storage, read> word_list: array<Word, 2048>;

struct Word {
    bytes: array<u32, 8>,
    length: u32,
};

@group(0) @binding(3)
var<storage, read_write> output: array<array<u32, SHA512_HASH_LENGTH>, MAX_RESULTS_FOUND>;

fn swap_bytes(value: u32) -> u32 {
    return ((value & 0xFF) << 24) | (((value >> 8) & 0xFF) << 16) | (((value >> 16) & 0xFF) << 8) | ((value >> 24) & 0xFF);
}

// bind bip39::words or embed as constant
fn entropy_to_indices(entropy: array<u32, WORDS>) -> array<u32, 12> {
    // swap to BE
    var be_entropy = array<u32, 4>();
    for (var i = 0u; i < 4u; i++) {
        be_entropy[i] = swap_bytes(entropy[i]);
    }

    var out = array<u32, 12>();

    // 1st chunk
    out[0] = be_entropy[0] >> 21;
    out[1] = (be_entropy[0] << 11) >> 21;
    out[2] = ((be_entropy[0] << 22) >> 21) | (be_entropy[1] >> (32 - 1));

    // 2nd chunk
    out[3] = (be_entropy[1] << 1) >> 21;
    out[4] = (be_entropy[1] << 12) >> 21;
    out[5] = ((be_entropy[1] << 23) >> 21) | (be_entropy[2] >> (32 - 2));

    // 3rd chunk
    out[6] = (be_entropy[2] << 2) >> 21;
    out[7] = (be_entropy[2] << 13) >> 21;
    out[8] = ((be_entropy[2] << 24) >> 21) | (be_entropy[3] >> (32 - 3));

    // 4th chunk + Entropy
    out[9] = (be_entropy[3] << 3) >> 21;
    out[10] = (be_entropy[3] << 14) >> 21;
    out[11] = ((be_entropy[3] << 25) >> 21) | constants.checksum;

    return out;
}

// 12 words, max 8 characters with 11 spaces. That's 107 max bytes, 128 for ease of use with pbkdf2
const MNEMONIC_MAX_BYTES = 128;

fn indices_to_word(indices: array<u32, 12>, dest: ptr<function, array<u32, MNEMONIC_MAX_BYTES>>) -> u32 {
    // Convert indices to word bytes
    var cursor = 0u;

    for (var i = 0; i < 12; i++) {
        let index = indices[i];
        let word = word_list[index];

        for (var j = 0u; j < word.length; j++) {
            // Get the byte from the word, append to dest
            dest[cursor] = word.bytes[j];
            cursor += 1;
        }

        // append space if not last word
        if i != 11 {
            // ASCII space character
            dest[cursor] = 0x20u;
            cursor += 1;
        }
    }

    // return the number of bytes written
    return cursor;
}

@compute @workgroup_size(WORKGROUP_SIZE)
fn main(@builtin(global_invocation_id) global: vec3<u32>) {
    // generate indices for mnemonics words from entropy
    let word_2 = matches[global.x];

    var entropy = array<u32, WORDS>(constants.word0, constants.word1, word_2, constants.word3);
    var indices = entropy_to_indices(entropy);

    // extract word bytes and derive master extended key
    var word_bytes = array<u32, MNEMONIC_MAX_BYTES>();
    var length = indices_to_word(indices, &word_bytes);

    // b"mnemonic"
    var mnemonic = array<u32, 8>(109, 110, 101, 109, 111, 110, 105, 99);
    let mnemonic_len = 8u;

    var salt = array<u32, SHA512_MAX_INPUT_SIZE>();
    for (var i = 0u; i < mnemonic_len; i++) {
        salt[i] = mnemonic[i];
    }

    // TODO: avoid using an intermediate array, use storage buffer and index directly in functions
    // var master_key: array<u32, SHA512_HASH_LENGTH>;
    // pbkdf2(&word_bytes, length, &salt, mnemonic_len, 2048, &master_key);

    var scratch = array<u32, SHA512_HASH_LENGTH>();
    for (var i = 0; i < 12; i++) {
        scratch[i] = indices[i];
    }

    output[global.x] = scratch;
    // TODO: continue with derivation path
}