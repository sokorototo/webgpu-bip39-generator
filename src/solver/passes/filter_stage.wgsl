const WORKGROUP_SIZE = 256; // 2 ^ 8
const NEXT_PASS_WORKGROUP_SIZE = 256; // 2 ^ 8

const DISPATCH_SIZE_X = 256; // 2 ^ 8
const DISPATCH_SIZE_Y = 256; // 2 ^ 8

const THREAD_COUNT = 16777216; // WORKGROUP_SIZE * DISPATCH_SIZE_Y * DISPATCH_SIZE_X

const MAX_RESULTS_FOUND = 1398101;

struct PushConstants {
    word0: u32,
    word1: u32,
    word2_partial: u32,
    word3: u32,
    checksum: u32,
};

var<push_constant> constants: PushConstants;

@group(0) @binding(1)
var<storage, read_write> count: atomic<u32>;

@group(0) @binding(2)
var<storage, read_write> matches: array<u32, MAX_RESULTS_FOUND>;

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

    // word[2]: upper 24 bits of entropy come from global index, lower 8 bits are known
    var entropy_2 = (local.x << 16) | (workgroup_id.y << 8) | workgroup_id.x;
    var word_2 = constants.word2_partial | (entropy_2 << 8);

    // verify mnemonic checksum
    var entropy = array<u32, 4>(constants.word0, constants.word1, word_2, constants.word3);
    var short256 = short256(entropy);

    // if entropy matches, queue for next stage
    if short256 >> 4 == constants.checksum {
        var index = atomicAdd(&count, 1u);
        matches[index] = word_2;
    }
}
