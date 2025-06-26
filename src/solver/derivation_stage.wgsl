const WORKGROUP_SIZE = 128; // 2 ^ 7
const DISPATCH_SIZE = 32768; // 2 ^ 15
const THREAD_COUNT = 4194304; // 2 ^ 22

const P2PKH_ADDRESS_SIZE = 20;

@group(0) @binding(0)
var<storage, read_write> dispatch: array<u32, 4>;

@group(0) @binding(1)
var<storage, read_write> entropies: array<array<u32, 4>, MAX_RESULTS_FOUND>;

@group(0) @binding(2)
var<storage, read_write> address: array<u32, P2PKH_ADDRESS_SIZE>;

// bind bip39::words or embed as constant

fn htobe32(x: u32) -> u32 {
    let b0 = (x >> 24) & 0x000000FFu;
    let b1 = (x >> 8) & 0x0000FF00u;
    let b2 = (x << 8) & 0x00FF0000u;
    let b3 = (x << 24) & 0xFF000000u;
    return b0 | b1 | b2 | b3;
}

fn entropy_to_indices(entropy: array<u32, 4>, checksum: u32) -> array<u32, 12> {
    var entropy_be = array<u32, 4>(htobe32(entropy[0]), htobe32(entropy[1]), htobe32(entropy[2]), htobe32(entropy[3]));
    var out = array<u32, 12>();

    // 1st chunk
    out[0] = (entropy_be[0] << 0) >> 21;
    out[1] = (entropy_be[0] << 11) >> 21;
    out[2] = ((entropy_be[0] << 22) >> 21) | (entropy_be[1] >> (32 - 1));

    // 2nd chunk
    out[3] = (entropy_be[1] << 1) >> 21;
    out[4] = (entropy_be[1] << 12) >> 21;
    out[5] = ((entropy_be[1] << 23) >> 21) | (entropy_be[2] >> (32 - 2));

    // 3rd chunk
    out[6] = (entropy_be[2] << 2) >> 21;
    out[7] = (entropy_be[2] << 13) >> 21;
    out[8] = ((entropy_be[2] << 24) >> 21) | (entropy_be[3] >> (32 - 3));

    // 4th chunk + Entropy
    out[9] = (entropy_be[3] << 3) >> 21;
    out[10] = (entropy_be[3] << 14) >> 21;
    out[11] = ((entropy_be[3] << 25) >> 21) | checksum;

    return out;
}

