// take 4 buffers as input
const INPUTS = 4;

struct Input {
    data: array<u32, 256>,
    len: u32
};

@group(0) @binding(0) var<storage, read> inputs: array<Input, INPUTS>;
@group(0) @binding(1) var<storage, read_write> output: array<array<u32, 64>, INPUTS>;

@compute @workgroup_size(INPUTS)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    var ctx: SHA512_CTX;
    var input: Input = inputs[id.x];

	// hash
    sha512_init(&ctx);
    sha512_update(&ctx, &input.data, input.len);

    var hash = sha512_done(&ctx);
    output[id.x] = hash;
}
