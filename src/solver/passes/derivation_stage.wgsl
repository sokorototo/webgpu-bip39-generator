const WORKGROUP_SIZE = 256; // 2 ^ 8
const THREAD_COUNT = 16777216; // 2 ^ 22

const P2PKH_ADDRESS_SIZE = 20;

@group(0) @binding(0) // X Y Z COUNT
var<storage, read> dispatch: array<u32, 4>;

@group(0) @binding(1)
var<storage, read> entropies: array<array<u32, 4>, MAX_RESULTS_FOUND>;

@group(0) @binding(2)
var<storage, read_write> address: array<u32, P2PKH_ADDRESS_SIZE>;

// bind bip39::words or embed as constant
fn entropy_to_indices(entropy: array<u32, 4>, checksum: u32) -> array<u32, 12> {
    var out = array<u32, 12>();

    // 1st chunk
    out[0] = entropy[0] >> 21;
    out[1] = (entropy[0] << 11) >> 21;
    out[2] = ((entropy[0] << 22) >> 21) | (entropy[1] >> (32 - 1));

    // 2nd chunk
    out[3] = (entropy[1] << 1) >> 21;
    out[4] = (entropy[1] << 12) >> 21;
    out[5] = ((entropy[1] << 23) >> 21) | (entropy[2] >> (32 - 2));

    // 3rd chunk
    out[6] = (entropy[2] << 2) >> 21;
    out[7] = (entropy[2] << 13) >> 21;
    out[8] = ((entropy[2] << 24) >> 21) | (entropy[3] >> (32 - 3));

    // 4th chunk + Entropy
    out[9] = (entropy[3] << 3) >> 21;
    out[10] = (entropy[3] << 14) >> 21;
    out[11] = ((entropy[3] << 25) >> 21) | checksum;

    return out;
}

