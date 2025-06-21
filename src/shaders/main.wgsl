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
var<storage, read_write> results: array<array<u32, P2PKH_ADDRESS_SIZE>, MAX_RESULTS_FOUND>;

@group(0) @binding(3)
var<storage, read> target_address: array<u32, P2PKH_ADDRESS_SIZE>;

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
    var input = array<u32, KIBBLE_COUNT>(constants.word0, combined_2, combined_3, constants.word3);
    var short256 = short256(input);

    if (short256[0] & constants.checksum) != short256[0] {
        return;
    }

    // 

    var index = atomicAdd(&count, 1u);
    results[index] = array<u32, P2PKH_ADDRESS_SIZE>(
        entropy_2, constants.entropy, combined_2, combined_3,
        short256[0], short256[1], short256[2], short256[3],
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    );
}
