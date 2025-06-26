use super::*;
use wgpu::util::DeviceExt;

pub(crate) struct FilterPass {
	pub pipeline: wgpu::ComputePipeline,
	pub bind_group: wgpu::BindGroup,
	pub entropies_buffer: wgpu::Buffer,
	pub count_buffer: wgpu::Buffer,
}

impl FilterPass {
	pub(crate) const WORKGROUP_SIZE: u32 = 64; // 2 ^ 6
	pub(crate) const DISPATCH_SIZE_X: u32 = 256; // 2 ^ 8
	pub(crate) const DISPATCH_SIZE_Y: u32 = 256; // 2 ^ 8
}

pub(crate) fn filter_pass(device: &wgpu::Device) -> FilterPass {
	debug_assert!(
		std::mem::size_of::<types::PushConstants>() as u32 <= device.limits().max_push_constant_size,
		"PushConstants too large for device, unable to init pipeline"
	);

	// prepare layout descriptor
	let dispatch_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("solver::dispatch"),
		contents: bytemuck::cast_slice(&[1, 1, 1, 0u32]),
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::INDIRECT,
	});

	let count_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("solver::count"),
		contents: bytemuck::cast_slice(&[0]),
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_WRITE,
	});

	let entropies_buffer = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("solver::entropies"),
		size: (std::mem::size_of::<types::Entropy>() * MAX_RESULTS_FOUND as usize) as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
		mapped_at_creation: false,
	});

	// compile shader
	let source = concat!(include_str!("../shaders/short256.wgsl"), include_str!("filter_stage.wgsl"));
	let descriptor = wgpu::ShaderModuleDescriptor {
		label: Some("filter::shader"),
		source: wgpu::ShaderSource::Wgsl(source.into()),
	};

	#[cfg(debug_assertions)]
	let shader = device.create_shader_module(descriptor);
	#[cfg(not(debug_assertions))]
	let shader = unsafe { device.create_shader_module_trusted(descriptor, wgpu::ShaderRuntimeChecks::unchecked()) };

	// configure bind group layout
	let descriptor = wgpu::BindGroupLayoutDescriptor {
		label: Some("filter::bind-group-layout"),
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
	};

	let bind_group_layout = device.create_bind_group_layout(&descriptor);

	// configure bind groups
	let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
		label: Some("filter::bind_group"),
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
				resource: entropies_buffer.as_entire_binding(),
			},
		],
	});

	// configure pipeline layout
	let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
		label: Some("filter::pipeline-layout"),
		bind_group_layouts: &[&bind_group_layout],
		push_constant_ranges: &[wgpu::PushConstantRange {
			stages: wgpu::ShaderStages::COMPUTE,
			range: 0..std::mem::size_of::<types::PushConstants>() as u32,
		}],
	});

	// create compute pipeline
	let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
		label: Some("filter::pipeline"),
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
		entropies_buffer,
		count_buffer,
	}
}
