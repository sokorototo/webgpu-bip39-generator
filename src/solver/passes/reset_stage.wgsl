// simply resets counter buffer on the GPU
const WORKGROUP_SIZE = 1;

@group(0) @binding(WORKGROUP_SIZE)
var<storage, read_write> count: atomic<u32>;

@compute @workgroup_size(1)
fn main() {
    atomicStore(&count, 0u);
}
