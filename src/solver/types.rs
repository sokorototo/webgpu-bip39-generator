#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct Bip39Word {
	pub(crate) bytes: [u32; 8],
	pub(crate) length: u32,
}

/// Represents a 64bit sha512 hash as an array of 32-bit integers
pub(crate) type GpuSha512Hash = [u32; 64];
/// The middle 2 words of a mnemonic word, that match the given checksum
pub(crate) type Match = [u32; 2];
/// Represents a verified P2PKH address as a 20-byte hash
pub(crate) type PublicKeyHash = [u32; 20];
