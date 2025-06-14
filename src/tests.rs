use sha256_rs::sha256;
use wgpu::util::DeviceExt;

use super::*;

const KIBBLE_SIZE: usize = 4;
const INPUTS: usize = 16;

const INPUT_BUFFER_SIZE: usize = std::mem::size_of::<u32>() * KIBBLE_SIZE * INPUTS;
const OUTPUT_BUFFER_SIZE: usize = std::mem::size_of::<u32>() * INPUTS;

fn verify(gpu_input: [u8; INPUT_BUFFER_SIZE], cpu_input: [[u8; KIBBLE_SIZE]; INPUTS]) {
	let mut gpu_extracted = [[0u8; KIBBLE_SIZE]; INPUTS];

	let gpu_bytes = gpu_input
		.chunks_exact(std::mem::size_of::<u32>())
		.map(|w| {
			let mut le_bytes = [0u8; 4];
			le_bytes.copy_from_slice(w);
			u32::from_le_bytes(le_bytes) as u8
		})
		.collect::<Vec<_>>();

	assert_eq!(gpu_bytes.len(), INPUTS * KIBBLE_SIZE);

	for (idx, bytes) in gpu_bytes.chunks_exact(KIBBLE_SIZE).enumerate() {
		let mut target = [0u8; KIBBLE_SIZE];
		target.copy_from_slice(bytes);
		gpu_extracted[idx] = target;
	}

	assert_eq!(gpu_extracted, cpu_input);
}

#[test]
fn test_sha256_implementation() {
	// input is 16 * 4-byte words
	let mut input = [[0u8; KIBBLE_SIZE]; INPUTS];
	for word in input.iter_mut() {
		for byte in word {
			*byte = simplerand::rand();
		}
	}

	// Map each u8 to a u32, as u8 isn't supported in wgpu
	let gpu_input = input.map(|w| w.map(|i| i as u32));
	let gpu_input: [u8; INPUT_BUFFER_SIZE] = unsafe { std::mem::transmute(gpu_input) };

	// verify memory layout
	verify(gpu_input, input);

	// init device
	let (device, queue) = device::init();

	// initialize input buffers
	let input_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("test-sha256::input"),
		contents: &gpu_input,
		usage: wgpu::BufferUsages::STORAGE,
	});

	let output_buffer = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("test-sha256::output"),
		size: OUTPUT_BUFFER_SIZE as u64,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// get shaders
	let test_sha256 = include_str!("shaders/testsha256.wgsl");
	let short256 = include_str!("shaders/short256.wgsl");

	let source = format!("{}\n{}", short256, test_sha256);

	// compile shader
	let descriptor = wgpu::ShaderModuleDescriptor {
		label: Some("test-sha256::main"),
		source: wgpu::ShaderSource::Wgsl(source.into()),
	};
	let shader = device.create_shader_module(descriptor);

	// configure bind group layout
	let descriptor = wgpu::BindGroupLayoutDescriptor {
		label: Some("test-sha256::layout"),
		entries: &[
			wgpu::BindGroupLayoutEntry {
				binding: 0,
				visibility: wgpu::ShaderStages::COMPUTE,
				ty: wgpu::BindingType::Buffer {
					ty: wgpu::BufferBindingType::Storage { read_only: true },
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
		],
	};

	let bind_group_layout = device.create_bind_group_layout(&descriptor);

	// configure bind groups
	let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
		label: Some("test-sha256::bind_group"),
		layout: &bind_group_layout,
		entries: &[
			wgpu::BindGroupEntry {
				binding: 0,
				resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
					buffer: &input_buffer,
					offset: 0,
					size: None,
				}),
			},
			wgpu::BindGroupEntry {
				binding: 1,
				resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
					buffer: &output_buffer,
					offset: 0,
					size: None,
				}),
			},
		],
	});

	// configure pipeline layout
	let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
		label: Some("test-sha256::layout"),
		bind_group_layouts: &[&bind_group_layout],
		push_constant_ranges: &[],
	});

	// create compute pipeline
	let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
		label: Some("test-sha256::pipeline"),
		module: &shader,
		entry_point: Some("main"),
		layout: Some(&pipeline_layout),
		// defaults
		cache: None,
		compilation_options: Default::default(),
	});

	// create command encoder
	let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("test-sha256::encoder") });

	// queue commands
	let descriptor = wgpu::ComputePassDescriptor {
		label: Some("test-sha256::compute_pass"),
		timestamp_writes: None,
	};

	{
		let mut p = encoder.begin_compute_pass(&descriptor);

		p.set_pipeline(&pipeline);
		p.set_bind_group(0, &bind_group, &[]);
		p.dispatch_workgroups(1, 1, 1);
	}

	// submit commands
	let commands = encoder.finish();
	queue.submit([commands]);

	// read output buffer
	output_buffer.clone().map_async(wgpu::MapMode::Read, .., move |res| {
		if let Ok(_) = res {
			let view = output_buffer.slice(..).get_mapped_range();
			let mut gpu_output = [0u8; OUTPUT_BUFFER_SIZE];
			gpu_output.copy_from_slice(&view);

			// parse as u8 instead of u32, other 3 bytes are simply never populated
			let gpu_output = gpu_output.chunks_exact(std::mem::size_of::<u32>()).map(|w| w[0]).collect::<Vec<_>>();

			// generate short256 on CPU
			let cpu_output = input.map(|k| sha256(&k)[0]);
			assert_eq!(cpu_output.as_slice(), gpu_output.as_slice());
		}
	});
}
