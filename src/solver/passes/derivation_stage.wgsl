// dispatch size is dynamic, through dispatch_indirect: X=*,Y=*,Z=1
const WORKGROUP_SIZE = 256; // 2 ^ 8
const P2PKH_ADDRESS_SIZE = 20;

const MAX_RESULTS_FOUND = 1398101;
const ENTROPIES = 4;

// same as filter stage, most fields ignored
struct PushConstants {
    word0: u32,
    word1: u32,
    word3: u32,
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

fn swap_bytes(value: u32) -> u32 {
    let byte0 = value & 0xFF;
    let byte1 = (value >> 8) & 0xFF;
    let byte2 = (value >> 16) & 0xFF;
    let byte3 = (value >> 24) & 0xFF;

    return (byte0 * 0x1000000) | (byte1 * 0x10000) | (byte2 * 0x100) | byte3;
}

fn entropy_to_indices(entropy: array<u32, ENTROPIES>) -> array<u32, 12> {
    var out = array<u32, 12>();

    // 1st chunk - extracting 11-bit values from entropy[0]
    out[0] = entropy[0] >> 21;
    out[1] = (entropy[0] >> 10) & 0x7FF;
    out[2] = ((entropy[0] & 0x3FF) * 2) | (entropy[1] >> 31);

    out[3] = (entropy[1] >> 20) & 0x7FF;
    // 2nd chunk - extracting from entropy[1]
    out[4] = (entropy[1] >> 9) & 0x7FF;
    out[5] = ((entropy[1] & 0x1FF) * 4) | (entropy[2] >> 30);

    // 3rd chunk - extracting from entropy[2]
    out[6] = (entropy[2] >> 19) & 0x7FF;
    out[7] = (entropy[2] >> 8) & 0x7FF;
    out[8] = ((entropy[2] & 0xFF) * 8) | (entropy[3] >> 29);

    // 4th chunk - extracting from entropy[3] + checksum
    out[9] = (entropy[3] >> 18) & 0x7FF;
    out[10] = (entropy[3] >> 7) & 0x7FF;
    out[11] = ((entropy[3] & 0x7F) * 16) | (constants.checksum & 0xF);

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

@group(0) @binding(3)
var<storage, read_write> output: array<array<u32, SHA512_HASH_LENGTH>, MAX_RESULTS_FOUND>;

@compute @workgroup_size(WORKGROUP_SIZE)
fn main(@builtin(global_invocation_id) global: vec3<u32>) {
    // generate indices for mnemonics words from entropy
    let word_2 = matches[global.x];

    var entropy = array<u32, ENTROPIES>(constants.word0, constants.word1, word_2, constants.word3);
    var indices = entropy_to_indices(entropy);

    // extract word
    var word_bytes = array<u32, MNEMONIC_MAX_BYTES>();
    var length = indices_to_word(indices, &word_bytes);

    // b"mnemonic"
    var mnemonic = array<u32, 8>(109, 110, 101, 109, 111, 110, 105, 99);
    let mnemonic_len = 8u;

    // TODO: consolidate usage of _128 scratch buffers? monomorphised functions, buffer re-use
    var mnemonic_128 = array<u32, SHA512_MAX_INPUT_SIZE>();
    for (var i = 0u; i < mnemonic_len; i++) {
        mnemonic_128[i] = mnemonic[i];
    }

    // derive mnemonic seed
    var seed: array<u32, SHA512_HASH_LENGTH>;
    pbkdf2(&word_bytes, length, &mnemonic_128, mnemonic_len, 2048, &seed);

    var seed_128 = array<u32, SHA512_MAX_INPUT_SIZE>();
    for (var i = 0u; i < SHA512_HASH_LENGTH; i++) {
        seed_128[i] = seed[i];
    }

    // derive master extended key
    var key = array<u32, 12>(66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100); // b"Bitcoin seed"

    var key_128 = array<u32, SHA512_MAX_INPUT_SIZE>();
    for (var i = 0u; i < 12u; i++) {
        key_128[i] = key[i];
    }

    // first 32 bytes are private key, 2nd 32 bytes are chain code
    var master_extended_key: array<u32, SHA512_HASH_LENGTH>;
    hmac_sha512(&seed_128, SHA512_HASH_LENGTH, &key_128, &master_extended_key);

    // derivation path = m/44'/0'/0'/0/0
    output[global.x] = master_extended_key;
    // TODO: continue with derivation path
}