const WORKGROUP_SIZE = 256; // 2 ^ 8

const DISPATCH_SIZE_X = 256; // 2 ^ 8
const DISPATCH_SIZE_Y = 256; // 2 ^ 8

const THREAD_COUNT = 16777216; // WORKGROUP_SIZE * DISPATCH_SIZE_Y * DISPATCH_SIZE_X

const MAX_RESULTS_FOUND = 2097152;
const CHUNKS = 4;

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

@group(0) @binding(0) // X Y Z: X = COUNT
var<storage, read_write> dispatch: array<u32, 3>;

@group(0) @binding(1)
var<storage, read_write> count: atomic<u32>;

@group(0) @binding(2)
var<storage, read_write> entropies: array<array<u32, CHUNKS>, MAX_RESULTS_FOUND>;

// TODO: Compress cryptographic functions from sparse to dense u32s

// workgroups: (2 ^ 8, 1, 1) rectangles, basically 1D
// dispatch: (2 ^ 8, 2 ^ 8, 1), but we index into the space depending on the offset
@compute @workgroup_size(WORKGROUP_SIZE)
fn main(
    @builtin(local_invocation_id) local: vec3<u32>,
    @builtin(workgroup_id) workgroup_id: vec3<u32>
) {
    if atomicLoad(&count) >= MAX_RESULTS_FOUND {
        return;
    }

    // word[1]: lower 20 bits of entropy come from push_constants::entropy, upper 12 bits are known
    let combined_2 = constants.word1 | constants.entropy;

    // word[2]: upper 24 bits of entropy come from global index, lower 8 bits are known
    var entropy_3 = (local.x << 16) | (workgroup_id.y << 8) | workgroup_id.x;
    let combined_3 = constants.word2 | (entropy_3 << 8);

    // verify mnemonic checksum
    var entropy = array<u32, 4>(constants.word0, combined_2, combined_3, constants.word3);
    var short256 = short256(entropy);

    // insert entropy for next pass
    if short256 >> 4 == constants.checksum {
        var index = atomicAdd(&count, 1u);
        entropies[index] = entropy;

        // update entropies count
        dispatch[0] = (index + 1);
    }
}
