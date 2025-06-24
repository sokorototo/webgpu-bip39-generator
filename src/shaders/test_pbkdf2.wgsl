// take 4 buffers as input
const INPUTS = 4;

struct Input {
    data: array<u32, SHA512_MAX_INPUT_SIZE>,
    len: u32
};

@group(0) @binding(0) var<storage, read> inputs: array<Input, INPUTS>;
@group(0) @binding(1) var<storage, read_write> output: array<array<u32, SHA512_HASH_LENGTH>, INPUTS>;

@compute @workgroup_size(INPUTS)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    var input = inputs[id.x];

    // copy data to function storage
    var data = array<u32, SHA512_MAX_INPUT_SIZE>();
    for (var i = 0u; i < input.len; i++) {
        data[i] = input.data[i];
    }

	// b"mnemonic"
    var mnemonic = array<u32, 8>(109, 110, 101, 109, 111, 110, 105, 99);
    var salt = array<u32, SHA512_MAX_INPUT_SIZE>();

    for (var i = 0; i < 8; i++) {
        salt[i] = mnemonic[i];
    }

    // poop output
    output[id.x] = pbkdf2(&data, input.len, &salt, 8, 2048);
}
