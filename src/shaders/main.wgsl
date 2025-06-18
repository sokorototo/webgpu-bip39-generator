const WORKGROUP_SIZE = 64; // 2 ^ 6
const DISPATCH_SIZE = 65536; // 2 ^ 16
const THREAD_COUNT = 4194304; // WORKGROUP_SIZE * DISPATCH_SIZE
const MAX_RESULTS_FOUND = 65536; // ARRAY_MAX_SIZE

// NOTE: 3rd word is unknown
struct Word {
    bits: u32,
    checksum: u32
};

struct PushConstants {
  items: array<Word, 4>,
};

var<push_constant> words: PushConstants;

@group(0) @binding(1)
var<storage, read_write> count: atomic<u32>; // MAX_RESULTS_FOUND

@group(0) @binding(2)
var<storage, read_write> results: array<Word, MAX_RESULTS_FOUND>;

// TODO: input target addresses

fn extract_bytes(input: u32) -> array<u32, 4> {
    var bytes: array<u32, 4>;

    bytes[0] = (input >> 0u) & 0xFFu;
    bytes[1] = (input >> 8u) & 0xFFu;
    bytes[2] = (input >> 16u) & 0xFFu;
    bytes[3] = (input >> 24u) & 0xFFu;

    return bytes;
}

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
    var bytes = extract_bytes(combined);

    var short256 = short256(bytes);
    if (short256 & checksum) != short256 {
        return;
    }

    var index = atomicAdd(&count, 1u);
    results[index] = Word(combined, checksum);
}
