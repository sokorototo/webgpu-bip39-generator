const P2PKH_ADDRESS_SIZE: usize = 20;
const ENTROPY_COUNT: usize = 4;

#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct PushConstants {
	pub(crate) words: [u32; 4],
	pub(crate) entropy: u32,
	/// Checksum is 1 or 0
	pub(crate) checksum: u32,
}

#[allow(non_camel_case_types)]
pub(crate) type Entropy = [u32; ENTROPY_COUNT];

#[allow(non_camel_case_types)]
pub(crate) type P2PKH_Address = [u32; P2PKH_ADDRESS_SIZE];
