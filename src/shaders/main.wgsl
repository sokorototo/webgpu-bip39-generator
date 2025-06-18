const WORKGROUP_SIZE = 64; // 2 ^ 6
const DISPATCH_SIZE = 65536; // 2 ^ 16
const THREAD_COUNT = 4194304; // WORKGROUP_SIZE * DISPATCH_SIZE
const MAX_RESULTS_FOUND = 65536; // ARRAY_MAX_SIZE

const P2PKH_ADDRESS_SIZE = 20;

struct PushConstants {
    word0: u32,
    word1: u32,
    word2: u32,
    word3: u32,
    entropy: u32,
    checksum: u32,
};

var<push_constant> words: PushConstants;

@group(0) @binding(1)
var<storage, read_write> count: atomic<u32>;

@group(0) @binding(2)
var<storage, read_write> results: array<array<u32, P2PKH_ADDRESS_SIZE>, MAX_RESULTS_FOUND>;

@group(0) @binding(3)
var<storage, read> target_address: array<u32, P2PKH_ADDRESS_SIZE>;

// workgroups: (2 ^ 6, 1, 1) rectangles, basically 1D
// dispatch: (2 ^ 16, 1, 1), but we index into the space depending on the offset
@compute @workgroup_size(WORKGROUP_SIZE)
fn main(
    @builtin(local_invocation_id) local: vec3<u32>,
    @builtin(workgroup_id) workgroup_id: vec3<u32>
) {
    if atomicLoad(&count) >= MAX_RESULTS_FOUND {
        return;
    }

     // lower 22 bits of entropy come from local index
    var entropy = (workgroup_id.x * DISPATCH_SIZE) + local.x;
    var bits = words.items[2].bits;
    var checksum = words.items[2].checksum;

     // upper 10 bits are known: combine, hash and check
    let combined = bits | entropy;
    var short256 = short256(bytes);

    if (short256 & checksum) != short256 {
        return;
    }

     // TODO: extract upper 22 bits of entropy from push_constants::checksum

    var index = atomicAdd(&count, 1u);
    results[index] = Word(combined, entropy);
}
