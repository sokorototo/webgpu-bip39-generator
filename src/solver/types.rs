#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct Bip39Word {
	pub(crate) bytes: [u32; 8],
	pub(crate) length: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable, PartialEq)]
pub(crate) struct DerivationsOutput {
	/// variant word for this output
	pub(crate) word2: u32,
	/// sha512, represented as a 32bit array
	pub(crate) hash: [u32; 64],
}

/// The 3rd word of a mnemonic sequence, that matches the given checksum when combined with entropy
pub(crate) type Word = u32;
/// Represents a verified P2PKH address as a 20-byte hash
pub(crate) type PublicKeyHash = [u8; 20];
