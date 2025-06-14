// with 16 kibbles as input
const INPUTS = 16;

@group(0) @binding(0) var<storage, read> kibbles: array<array<u32, KIBBLE_SIZE>, INPUTS>;
@group(0) @binding(1) var<storage, read_write> expected: array<u32, INPUTS>;

@compute @workgroup_size(INPUTS)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    var kibble: array<u32, KIBBLE_SIZE> = kibbles[id.x];
	 var hash: array<u32, SHA256_BLOCK_SIZE> = short256(kibble);

	 expected[id.x] = hash[0];
}
