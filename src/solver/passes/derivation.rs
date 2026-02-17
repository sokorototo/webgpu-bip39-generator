use super::super::*;
use wgpu::util::DeviceExt;

#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct Immediates {
	pub(crate) word0: u32,
	pub(crate) word1: u32,
	pub(crate) word3: u32,
	pub(crate) checksum: u32,
	pub(crate) offset: u32,
	pub(crate) count: u32,
}

pub(crate) struct DerivationPass {
	pub constants: Immediates,
	pub pipeline: wgpu::ComputePipeline,
	pub bind_group: wgpu::BindGroup,
	pub output_buffer: wgpu::Buffer,
	pub output_buffer_dest: wgpu::Buffer,
}

impl DerivationPass {
	pub(crate) const WORKGROUP_SIZE: u32 = 256;

	pub(crate) fn new(device: &wgpu::Device, filter_pass: &filter::FilterPass) -> DerivationPass {
		assert!(
			std::mem::size_of::<Immediates>() as u32 <= device.limits().max_immediate_size,
			"filter::PushConstants too large for device, unable to init pipeline"
		);

		// prepare buffers
		let word_list_buffer = {
			// allocate word list buffer
			let words = bip39::Language::English
				.word_list()
				.into_iter()
				.map(|word| {
					let bytes = word.as_bytes();

					let mut buffer = [0u8; 8];
					(&mut buffer[..bytes.len()]).copy_from_slice(bytes);

					types::Bip39Word {
						bytes: buffer.map(|s| s as u32),
						length: bytes.len() as u32,
					}
				})
				.collect::<Vec<_>>();

			let descriptor = wgpu::util::BufferInitDescriptor {
				label: Some("derivation_word_list"),
				contents: bytemuck::cast_slice(&words),
				usage: wgpu::BufferUsages::STORAGE,
			};

			device.create_buffer_init(&descriptor)
		};

		let output_buffer = device.create_buffer(&wgpu::BufferDescriptor {
			label: Some("derivation_outputs"),
			size: (std::mem::size_of::<[types::DerivationsOutput; MAX_RESULTS_FOUND]>() as usize) as wgpu::BufferAddress,
			usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
			mapped_at_creation: false,
		});

		let output_buffer_dest = device.create_buffer(&wgpu::BufferDescriptor {
			label: Some("derivation_outputs"),
			size: (std::mem::size_of::<[types::DerivationsOutput; MAX_RESULTS_FOUND]>() as usize) as wgpu::BufferAddress,
			usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
			mapped_at_creation: false,
		});

		// compile shader
		let source = concat!(include_str!("../../shaders/sha512.wgsl"), include_str!("../../shaders/pbkdf2.wgsl"), include_str!("derivation_stage.wgsl"));
		let descriptor = wgpu::ShaderModuleDescriptor {
			label: Some("derivation_main"),
			source: wgpu::ShaderSource::Wgsl(source.into()),
		};

		let shader = device.create_shader_module(descriptor);

		// configure bind group layout
		let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
			label: Some("derivation_bind_group_layout"),
			entries: &[
				wgpu::BindGroupLayoutEntry {
					binding: 1,
					visibility: wgpu::ShaderStages::COMPUTE,
					ty: wgpu::BindingType::Buffer {
						ty: wgpu::BufferBindingType::Storage { read_only: true },
						has_dynamic_offset: false,
						min_binding_size: None,
					},
					count: None,
				},
				wgpu::BindGroupLayoutEntry {
					binding: 2,
					visibility: wgpu::ShaderStages::COMPUTE,
					ty: wgpu::BindingType::Buffer {
						ty: wgpu::BufferBindingType::Storage { read_only: true },
						has_dynamic_offset: false,
						min_binding_size: None,
					},
					count: None,
				},
				wgpu::BindGroupLayoutEntry {
					binding: 3,
					visibility: wgpu::ShaderStages::COMPUTE,
					ty: wgpu::BindingType::Buffer {
						ty: wgpu::BufferBindingType::Storage { read_only: false },
						has_dynamic_offset: false,
						min_binding_size: None,
					},
					count: None,
				},
			],
		});

		// configure bind groups
		let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
			label: Some("derivation_bind_group"),
			layout: &bind_group_layout,
			entries: &[
				wgpu::BindGroupEntry {
					binding: 1,
					resource: filter_pass.matches_buffer.as_entire_binding(),
				},
				wgpu::BindGroupEntry {
					binding: 2,
					resource: word_list_buffer.as_entire_binding(),
				},
				wgpu::BindGroupEntry {
					binding: 3,
					resource: output_buffer.as_entire_binding(),
				},
			],
		});

		// configure pipeline layout
		let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
			label: Some("derivation_pipeline_layout"),
			bind_group_layouts: &[&bind_group_layout],
			immediate_size: std::mem::size_of::<Immediates>() as u32,
		});

		// create compute pipeline
		let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
			label: Some("derivation_pipeline"),
			module: &shader,
			entry_point: Some("main"),
			layout: Some(&pipeline_layout),
			// defaults
			cache: None,
			compilation_options: Default::default(),
		});

		DerivationPass {
			pipeline,
			bind_group,
			output_buffer,
			output_buffer_dest,
			constants: Immediates {
				checksum: filter_pass.immediates.checksum,
				offset: 0,
				count: 0,
				word0: filter_pass.immediates.words[0],
				word1: 0,
				word3: filter_pass.immediates.words[3],
			},
		}
	}
}
