use super::super::*;
use wgpu::util::DeviceExt;

#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct PushConstants {
	pub(crate) words: [u32; 4],
	pub(crate) checksum: u32,
}

impl PushConstants {
	pub(crate) fn from_stencil<'a, I: Iterator<Item = &'a str>>(words: I) -> PushConstants {
		// map stencil to mnemonic
		let replaced = words.map(|s| if s == "_" { "abandon" } else { s }).collect::<Vec<_>>().join(" ");
		let mnemonic = bip39::Mnemonic::parse_in_normalized_without_checksum_check(bip39::Language::English, &replaced).unwrap();

		let entropy = mnemonic.to_entropy();

		// mnemonic is bigEndian: 💀
		let mut words = [0u32; 4];
		words.copy_from_slice(bytemuck::cast_slice(&entropy));
		words = words.map(|w| w.to_be()); // TODO: does this make sense?

		PushConstants {
			words,
			checksum: mnemonic.checksum() as _,
		}
	}
}

pub(crate) struct FilterPass {
	pub constants: PushConstants,
	pub pipeline: wgpu::ComputePipeline,
	pub bind_group: wgpu::BindGroup,
	pub matches_buffer: wgpu::Buffer,
	pub count_buffer: wgpu::Buffer,
	pub dispatch_buffer: wgpu::Buffer,
}

impl FilterPass {
	pub(crate) const WORKGROUP_SIZE: u32 = 256; // 2 ^ 8
	pub(crate) const DISPATCH_SIZE_X: u32 = 256; // 2 ^ 8
	pub(crate) const DISPATCH_SIZE_Y: u32 = 256; // 2 ^ 8

	pub(crate) fn new<'a, I: Iterator<Item = &'a str>>(device: &wgpu::Device, stencil: I) -> FilterPass {
		assert!(
			std::mem::size_of::<PushConstants>() as u32 <= device.limits().max_push_constant_size,
			"filter::PushConstants too large for device, unable to init pipeline"
		);

		// prepare buffers
		let dispatch_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
			label: Some("solver_dispatch"),
			contents: bytemuck::cast_slice(&[1, 1, 1u32]),
			usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::INDIRECT,
		});

		let count_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
			label: Some("solver_count"),
			contents: bytemuck::cast_slice(&[0]),
			usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_READ,
		});

		let matches_buffer = device.create_buffer(&wgpu::BufferDescriptor {
			label: Some("solver_matches"),
			size: (std::mem::size_of::<[types::Word2; MAX_RESULTS_FOUND]>() as usize) as wgpu::BufferAddress,
			usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
			mapped_at_creation: false,
		});

		// compile shader
		let source = concat!(include_str!("../../shaders/short256.wgsl"), include_str!("filter_stage.wgsl"));
		let descriptor = wgpu::ShaderModuleDescriptor {
			label: Some("filter_main"),
			source: wgpu::ShaderSource::Wgsl(source.into()),
		};

		#[cfg(debug_assertions)]
		let shader = device.create_shader_module(descriptor);
		#[cfg(not(debug_assertions))]
		let shader = unsafe { device.create_shader_module_trusted(descriptor, wgpu::ShaderRuntimeChecks::unchecked()) };

		// configure bind group layout
		let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
			label: Some("filter_bind_group_layout"),
			entries: &[
				wgpu::BindGroupLayoutEntry {
					binding: 0,
					visibility: wgpu::ShaderStages::COMPUTE,
					ty: wgpu::BindingType::Buffer {
						ty: wgpu::BufferBindingType::Storage { read_only: false },
						has_dynamic_offset: false,
						min_binding_size: None,
					},
					count: None,
				},
				wgpu::BindGroupLayoutEntry {
					binding: 1,
					visibility: wgpu::ShaderStages::COMPUTE,
					ty: wgpu::BindingType::Buffer {
						ty: wgpu::BufferBindingType::Storage { read_only: false },
						has_dynamic_offset: false,
						min_binding_size: None,
					},
					count: None,
				},
				wgpu::BindGroupLayoutEntry {
					binding: 2,
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
			label: Some("filter_bind_group"),
			layout: &bind_group_layout,
			entries: &[
				wgpu::BindGroupEntry {
					binding: 0,
					resource: dispatch_buffer.as_entire_binding(),
				},
				wgpu::BindGroupEntry {
					binding: 1,
					resource: count_buffer.as_entire_binding(),
				},
				wgpu::BindGroupEntry {
					binding: 2,
					resource: matches_buffer.as_entire_binding(),
				},
			],
		});

		// configure pipeline layout
		let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
			label: Some("filter_pipeline_layout"),
			bind_group_layouts: &[&bind_group_layout],
			push_constant_ranges: &[wgpu::PushConstantRange {
				stages: wgpu::ShaderStages::COMPUTE,
				range: 0..std::mem::size_of::<PushConstants>() as u32,
			}],
		});

		// create compute pipeline
		let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
			label: Some("filter_pipeline"),
			module: &shader,
			entry_point: Some("main"),
			layout: Some(&pipeline_layout),
			// defaults
			cache: None,
			compilation_options: Default::default(),
		});

		FilterPass {
			pipeline,
			bind_group,
			matches_buffer,
			count_buffer,
			dispatch_buffer,
			constants: PushConstants::from_stencil(stencil),
		}
	}
}
