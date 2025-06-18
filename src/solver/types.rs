#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct Word {
	pub(crate) bits: u32,
	pub(crate) checksum: u32,
}
