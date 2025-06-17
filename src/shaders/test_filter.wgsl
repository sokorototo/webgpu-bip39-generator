const WORKGROUP_SIZE = 64; // 2 ^ 6
const DISPATCH_SIZE = 65536; // 2 ^ 16
const THREAD_COUNT = 4194304; // WORKGROUP_SIZE * DISPATCH_SIZE
const MAX_RESULTS_FOUND = 65536; // ARRAY_MAX_SIZE

struct Uniforms {
    left_bits: u32,
    right_bits: u32,
	// we only care about the first 2 bits
    checksum: u32
};

@group(0) @binding(0)
var<uniform> knowns: Uniforms;

@group(0) @binding(1)
var<uniform> offset: u32; // MAX: 2 ^ 22

@group(0) @binding(2)
var<storage, read_write> count: atomic<u32>; // MAX_RESULTS_FOUND

struct Result {
    left: array<u32, 4>,
    right: array<u32, 4>,
};

@group(0) @binding(3)
var<storage, read_write> results: array<Result, MAX_RESULTS_FOUND>;

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

     // left 22 bits of entropy come from local index
    var left_entropy = (workgroup_id.x * DISPATCH_SIZE) + local.x;

     // right 22 bits of entropy come from offset
     // TODO: Right entropy will be the same for each dispatch which is wasted computation
    var right_entropy = offset;

     // calculate left entropy, checksum and verify match
    let left_test = knowns.left_bits | left_entropy;
    var left_bytes = extract_bytes(left_test);
    var left_short256 = short256(left_bytes);
    var left_matches = (left_short256 & knowns.checksum) == left_short256;

     // calculate right entropy, checksum and verify match
    let right_test = knowns.right_bits | (right_entropy << 10);
    var right_bytes = extract_bytes(right_test);
    var right_short256 = short256(right_bytes);
    var right_matches = (right_short256 & knowns.checksum) == right_short256;

    // // debug
    // var index = atomicAdd(&count, 1u);

    // var l_debug = array<u32, 4>(left_entropy, left_test, left_short256, left_short256 & 1);
    // var r_debug = array<u32, 4>(right_entropy, right_test, right_short256, right_short256 & 2);

    // results[index] = Result(l_debug, r_debug);

    // if both match add to discoveries
    if !(left_matches && right_matches) {
        return;
    }

    var index = atomicAdd(&count, 1u);
    results[index] = Result(left_bytes, right_bytes);
}
