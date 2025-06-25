const WORKGROUP_SIZE = 64; // 2 ^ 6

const DISPATCH_SIZE_X = 256; // 2 ^ 8
const DISPATCH_SIZE_Y = 256; // 2 ^ 8

const THREAD_COUNT = 4194304; // WORKGROUP_SIZE * DISPATCH_SIZE_Y * DISPATCH_SIZE_X

const MAX_RESULTS_FOUND = 65536; // ARRAY_MAX_SIZE
const P2PKH_ADDRESS_SIZE = 20;

struct PushConstants {
    word0: u32,
    word1: u32,
    word2: u32,
    word3: u32,
    // increments from 2^10 to 2^32
    entropy: u32,
    checksum: u32,
};

var<push_constant> constants: PushConstants;

@group(0) @binding(1)
var<storage, read_write> count: atomic<u32>;

@group(0) @binding(2)
var<storage, read_write> results: array<array<u32, 4>, MAX_RESULTS_FOUND>;

// workgroups: (2 ^ 6, 1, 1) rectangles, basically 1D
// dispatch: (2 ^ 8, 2 ^ 8, 1), but we index into the space depending on the offset
@compute @workgroup_size(WORKGROUP_SIZE)
fn main(
    @builtin(local_invocation_id) local: vec3<u32>,
    @builtin(workgroup_id) workgroup_id: vec3<u32>
) {
    if atomicLoad(&count) >= MAX_RESULTS_FOUND {
        return;
    }

    // evaluate local index: imagine a 256*256*64 cube
    var lower_cube = (DISPATCH_SIZE_X * DISPATCH_SIZE_Y * local.x);
    var lower_rect = DISPATCH_SIZE_X * workgroup_id.y;
    var lower_line = workgroup_id.x;

    // word[1]: lower 22 bits of entropy come from local index, upper 10 bits are known
    var entropy_2 = lower_cube + lower_rect + lower_line;
    let combined_2 = constants.word1 | entropy_2;

    // word[2]: upper 22 bits of entropy come from push_constants::entropy, lower 10 bits are known
    let combined_3 = constants.word2 | constants.entropy;

    // verify mnemonic checksum
    var entropy = array<u32, 4>(constants.word0, combined_2, combined_3, constants.word3);
    var short256 = short256(entropy);

    // if checksum doesn't match, skip
    if short256[0] >> 4 != constants.checksum {
        // TODO: instead of early exits employ multiple shader passes to Minimize Divergence
        return;
    } else {
        // insert entropy for next pass
        var index = atomicAdd(&count, 1u);
        results[index] = entropy;
    }
}


// TODO: Compress cryptographic functions from sparse to dense u32s
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

