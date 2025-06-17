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
fn test_short256_implementation() {
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
	let (device, queue) = pollster::block_on(device::init());

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

	// init shader
	let source = concat!(include_str!("shaders/short256.wgsl"), "\n", include_str!("shaders/test_short256.wgsl"));
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
				resource: input_buffer.as_entire_binding(),
			},
			wgpu::BindGroupEntry {
				binding: 1,
				resource: output_buffer.as_entire_binding(),
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

const MAX_RESULTS_FOUND: usize = 65536;

// A simple struct to represent the uniforms in Rust
#[repr(C)]
#[derive(Debug, Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
struct Knowns {
	left_bits: u32, // ideally left bits is very large
	right_bits: u32,
	checksum: u32,
}

// Struct to match the `Found` struct in WGSL
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
struct Match {
	left: [u32; 4],
	right: [u32; 4],
}

type Results = [Match; MAX_RESULTS_FOUND];

fn _verify_debug<'a, T: Iterator<Item = (usize, &'a Match)>>(matches: T, knowns: &Knowns) {
	let mut set = std::collections::BTreeSet::new();

	for (idx, _match) in matches {
		assert!(set.insert(_match.left[1]), "Duplicate Entropy Found: {}", _match.left[1]);

		let left_bytes = _match.left[1].to_le_bytes();
		let right_bytes = _match.right[1].to_le_bytes();

		let left_hash_bit = sha256(&left_bytes)[0];
		let right_hash_bit = sha256(&right_bytes)[0];

		assert_eq!(left_hash_bit, _match.left[2] as u8);
		assert_eq!(right_hash_bit, _match.right[2] as u8);
	}
}

fn verify_2<'a, T: Iterator<Item = (usize, &'a Match)>>(matches: T, knowns: &Knowns) {
	for (idx, _match) in matches {
		println!("[{}] = {:?}", idx, _match);

		let left_bits: [u8; 4] = _match.left.map(|s| s.try_into().unwrap());
		let right_bits: [u8; 4] = _match.right.map(|s| s.try_into().unwrap());

		let left_hash_bit = sha256(&left_bits)[0] & 0b1;
		let right_hash_bit = sha256(&right_bits)[0] & 0b10;

		assert_eq!(left_hash_bit & right_hash_bit, knowns.checksum as u8);

		let right = u32::from_le_bytes(right_bits) & 1023;
		let left = u32::from_le_bytes(left_bits) & 4290772992;

		assert_eq!(left, knowns.left_bits);
		assert_eq!(right, knowns.right_bits);
	}
}

#[test]
fn test_checksum_filters() {
	// init device
	let (device, queue) = pollster::block_on(device::init());

	// initialize uniforms
	let knowns = Knowns {
		left_bits: 0b0101 << 28,
		right_bits: 0b0110,
		checksum: 0,
	};

	let knowns_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("test-filter::knowns"),
		contents: bytemuck::cast_slice(&[knowns]),
		usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
	});

	let offset_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("test-filter::offset"),
		contents: bytemuck::cast_slice(&[78u32]),
		usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
	});

	let count_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("test-filter::count"),
		contents: bytemuck::cast_slice(&[0]),
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_READ,
	});

	// allocate buffer for `found` results.
	let results_buffer = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("test-filter::found"),
		size: (std::mem::size_of::<Results>()) as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// init shader
	let source = concat!(include_str!("shaders/short256.wgsl"), "\n", include_str!("shaders/test_filter.wgsl"));
	let descriptor = wgpu::ShaderModuleDescriptor {
		label: Some("test-filter::main"),
		source: wgpu::ShaderSource::Wgsl(source.into()),
	};

	let shader = device.create_shader_module(descriptor);

	// configure bind group layout
	let descriptor = wgpu::BindGroupLayoutDescriptor {
		label: Some("test-filter::layout"),
		entries: &[
			wgpu::BindGroupLayoutEntry {
				binding: 0,
				visibility: wgpu::ShaderStages::COMPUTE,
				ty: wgpu::BindingType::Buffer {
					ty: wgpu::BufferBindingType::Uniform,
					has_dynamic_offset: false,
					min_binding_size: None,
				},
				count: None,
			},
			wgpu::BindGroupLayoutEntry {
				binding: 1,
				visibility: wgpu::ShaderStages::COMPUTE,
				ty: wgpu::BindingType::Buffer {
					ty: wgpu::BufferBindingType::Uniform,
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
	};

	let bind_group_layout = device.create_bind_group_layout(&descriptor);

	// configure bind groups
	let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
		label: Some("test-filter::bind_group"),
		layout: &bind_group_layout,
		entries: &[
			wgpu::BindGroupEntry {
				binding: 0,
				resource: knowns_buffer.as_entire_binding(),
			},
			wgpu::BindGroupEntry {
				binding: 1,
				resource: offset_buffer.as_entire_binding(),
			},
			wgpu::BindGroupEntry {
				binding: 2,
				resource: count_buffer.as_entire_binding(),
			},
			wgpu::BindGroupEntry {
				binding: 3,
				resource: results_buffer.as_entire_binding(),
			},
		],
	});

	// configure pipeline layout
	let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
		label: Some("test-filter::layout"),
		bind_group_layouts: &[&bind_group_layout],
		push_constant_ranges: &[],
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

	// create command encoder
	let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("test-sha256::encoder") });

	{
		// queue commands
		let descriptor = wgpu::ComputePassDescriptor {
			label: Some("test-filter::compute_pass"),
			timestamp_writes: None,
		};

		let mut pass = encoder.begin_compute_pass(&descriptor);

		pass.set_pipeline(&pipeline);
		pass.set_bind_group(0, &bind_group, &[]);
		pass.dispatch_workgroups(32, 1, 1);
	}

	// submit commands
	let commands = encoder.finish();
	queue.submit([commands]);

	// wait for results to be ready
	let (send, recv) = std::sync::mpsc::sync_channel(1);
	count_buffer.clone().map_async(wgpu::MapMode::Read, .., move |res| {
		res.unwrap();
		let view = count_buffer.get_mapped_range(..);

		let results: &[u32] = bytemuck::cast_slice(view.as_ref());
		send.send(results[0]).unwrap();
	});

	results_buffer.clone().map_async(wgpu::MapMode::Read, .., move |res| {
		res.unwrap();
		let view = results_buffer.get_mapped_range(..);

		let results: &[Match] = bytemuck::cast_slice(view.as_ref());
		let count = recv.recv().unwrap();

		let matches = results.iter().enumerate().take(count as usize);

		verify_2(matches, &knowns);
		// verify_debug(matches, &knowns);
	});
}
