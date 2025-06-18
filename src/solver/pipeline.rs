use super::*;
use wgpu::util::DeviceExt;

pub(crate) fn create(device: &wgpu::Device, words: &[types::Word; 4]) -> (wgpu::ComputePipeline, wgpu::BindGroup, wgpu::Buffer, wgpu::Buffer) {
	assert!(
		std::mem::size_of_val(words) as u32 <= device.limits().max_push_constant_size,
		"Push Constants too small, unable to init pipeline"
	);

	// prepare layout descriptor
	let count_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("solver::count"),
		contents: bytemuck::cast_slice(&[0]),
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_WRITE,
	});

	let results_buffer = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("solver::results"),
		size: (std::mem::size_of::<types::Word>() * MAX_RESULTS_FOUND as usize) as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
		mapped_at_creation: false,
	});

	// init shader
	let source = concat!(include_str!("../shaders/short256.wgsl"), "\n", include_str!("../shaders/main.wgsl"));
	let descriptor = wgpu::ShaderModuleDescriptor {
		label: Some("solver::main"),
		source: wgpu::ShaderSource::Wgsl(source.into()),
	};

	let shader = device.create_shader_module(descriptor);

	// configure bind group layout
	let descriptor = wgpu::BindGroupLayoutDescriptor {
		label: Some("solver::bind-group-layout"),
		entries: &[
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
		label: Some("solver::bind_group"),
		layout: &bind_group_layout,
		entries: &[
			wgpu::BindGroupEntry {
				binding: 1,
				resource: count_buffer.as_entire_binding(),
			},
			wgpu::BindGroupEntry {
				binding: 2,
				resource: results_buffer.as_entire_binding(),
			},
		],
	});

	// configure pipeline layout
	let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
		label: Some("solver::pipeline-layout"),
		bind_group_layouts: &[&bind_group_layout],
		push_constant_ranges: &[wgpu::PushConstantRange {
			stages: wgpu::ShaderStages::COMPUTE,
			range: 0..std::mem::size_of_val(words) as u32,
		}],
	});

	// create compute pipeline
	let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
		label: Some("test-filter::pipeline"),
		module: &shader,
		entry_point: Some("main"),
		layout: Some(&pipeline_layout),
		// defaults
		cache: None,
		compilation_options: Default::default(),
	});

	(pipeline, bind_group, results_buffer, count_buffer)
}
