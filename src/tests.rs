use super::*;

use sha256_rs::sha256;
use wgpu::util::DeviceExt;

#[test]
fn test_stencil_to_word_array() {
	let samples = [
		"bundle beyond magnet scare legal cruise wash grid fury dutch utility dial",
		"small impose define destroy kingdom never gospel fold cement adjust rigid admit",
		"song person ask gaze visa judge merit school stick select gold orbit",
		"throw roast bulk opinion trick subway talent empower guide female change thought",
	];

	for sample in samples {
		let mnemonic = bip39::Mnemonic::parse(sample).unwrap();

		for (idx, word) in solver::map_stencil_to_words(sample.split(" ")).into_iter().enumerate() {
			assert_eq!((mnemonic.checksum() >> (4 - idx)) & word.checksum as u8, word.checksum as u8);
			assert_eq!(mnemonic.to_entropy_array().0[idx * 4..(idx + 1) * 4], word.bits.to_le_bytes());
		}
	}
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

#[allow(unused)]
fn verify_debug<'a, T: Iterator<Item = (usize, &'a Match)>>(matches: T, _knowns: &Knowns) {
	let mut left_set = std::collections::BTreeSet::new();

	for (_, _match) in matches {
		assert!(left_set.insert(_match.left[1]), "Duplicate Left Entropy Found: {}", _match.left[1]);

		let left_bytes = _match.left[1].to_le_bytes();
		let right_bytes = _match.right[1].to_le_bytes();

		let left_hash_bit = sha256(&left_bytes)[0];
		let right_hash_bit = sha256(&right_bytes)[0];

		assert_eq!(left_hash_bit, _match.left[2] as u8);
		assert_eq!(right_hash_bit, _match.right[2] as u8);
	}
}

fn verify_checksum<'a, T: Iterator<Item = (usize, &'a Match)>>(matches: T, knowns: &Knowns) {
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

		// queue copy commands
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

		verify_checksum(matches, &knowns);
		// verify_debug(matches, &knowns);
	});
}
