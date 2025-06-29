use super::*;
use sha2::Digest;
use wgpu::util::DeviceExt;

#[allow(unused)]
fn sha256(bytes: &[u8]) -> [u8; 32] {
	sha2::Sha256::digest(bytes).into()
}

#[allow(unused)]
fn sha512(bytes: &[u8]) -> [u8; 64] {
	sha2::Sha512::digest(bytes).into()
}

#[allow(unused)]
fn pbkdf2(bytes: &[u8]) -> [u8; 64] {
	pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 64>(bytes, b"mnemonic", 2048)
}

#[test]
fn verify_mnemonic_phrases() {
	let config = Config {
		stencil: ["zoo", "zoo", "zoo", "zoo", "_", "_", "_", "_", "zoo", "zoo", "zoo", "zoo"].map(|s| s.to_string()).into_iter().collect(),
		range: (0, 2048),
		address: parse_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap(),
	};

	// init devices
	let (device, queue) = pollster::block_on(device::init());

	// verify outputs
	let mut set = std::collections::BTreeSet::new();

	let callback = move |_, constants: &solver::passes::filter::PushConstants, matches: &[solver::types::Match]| {
		// verifies outputs from solver
		for match_ in matches {
			let match_ = [constants.words[0], match_[0], match_[1], constants.words[3]];
			let bytes: &[u8] = bytemuck::cast_slice(&match_);
			let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, bytes).unwrap();
			assert_eq!(constants.checksum as u8, mnemonic.checksum(), "Extracted Mnemonic Sequence has invalid checksum");

			// verify uniqueness
			assert!(set.insert(match_.clone()), "Duplicate Entropy Found: {:?}", match_);
		}
	};

	solver::solve(&config, &device, &queue, Some(solver::EntropyCallback(callback)));
}

#[test]
fn test_short256() {
	const INPUTS: usize = 4;

	// create inputs
	let inputs = [[12, 23, 45, 65], [00, 00, 00, 00], [16, 76, 89, 12], [255, 255, 255, 255u32]];

	// create device
	let (device, queue) = pollster::block_on(device::init());

	// prepare layout descriptor
	let kibbles_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("test-short256::kibbles"),
		contents: bytemuck::cast_slice(&inputs),
		usage: wgpu::BufferUsages::STORAGE,
	});

	let expected_buffer = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("test-short256::expected"),
		size: std::mem::size_of::<[u32; INPUTS]>() as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// init shader
	let sources = ["src/shaders/short256.wgsl", "src/tests/test_short256.wgsl"];
	let source = sources.into_iter().fold(String::new(), |acc, nxt| acc + "\n" + &std::fs::read_to_string(nxt).unwrap());

	let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
		label: Some("test_short256_main"),
		source: wgpu::ShaderSource::Wgsl(source.into()),
	});

	// configure bind group layout
	let descriptor = wgpu::BindGroupLayoutDescriptor {
		label: Some("test-short256::bind_group_layout"),
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
		label: Some("test-short256::bind_group"),
		layout: &bind_group_layout,
		entries: &[
			wgpu::BindGroupEntry {
				binding: 0,
				resource: kibbles_buffer.as_entire_binding(),
			},
			wgpu::BindGroupEntry {
				binding: 1,
				resource: expected_buffer.as_entire_binding(),
			},
		],
	});

	// configure pipeline layout
	let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
		label: Some("test-short256::pipeline_layout"),
		bind_group_layouts: &[&bind_group_layout],
		push_constant_ranges: &[],
	});

	// create compute pipeline
	let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
		label: Some("test-short256::pipeline"),
		module: &shader,
		entry_point: Some("main"),
		layout: Some(&pipeline_layout),
		// defaults
		cache: None,
		compilation_options: Default::default(),
	});

	// create command encoder
	let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("solver::encoder") });

	{
		// queue dispatch commands
		let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
			label: Some("test-short256::pass"),
			timestamp_writes: None,
		});

		pass.set_pipeline(&pipeline);
		pass.set_bind_group(0, &bind_group, &[]);

		// calculate dimensions of dispatch
		pass.dispatch_workgroups(INPUTS as _, 1, 1);
	}

	// submit commands
	let commands = encoder.finish();
	queue.submit([commands]);

	// read outputs buffer
	expected_buffer.clone().map_async(wgpu::MapMode::Read, .., move |res| {
		res.unwrap();

		let view = expected_buffer.get_mapped_range(..);
		let bytes: &[u32] = bytemuck::cast_slice(view.as_ref());

		for (idx, gpu_output) in bytes.iter().enumerate() {
			let cpu_output = sha256(bytemuck::cast_slice(&inputs[idx]));
			assert_eq!(*gpu_output, cpu_output[0] as u32, "HashBit Mismatch Between GPU and CPU",);
		}
	});

	// wait for tasks to finish
	device.poll(wgpu::PollType::Wait).unwrap();
}

#[test]
fn test_pbkdf2() {
	const INPUTS: usize = 4;
	const SHA512_MAX_INPUT_SIZE: usize = 128;
	const SHA512_HASH_LENGTH: usize = 64;

	#[repr(C)]
	#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
	struct Input {
		data: [u32; SHA512_MAX_INPUT_SIZE],
		len: u32,
	}

	// prepare test data
	let data: [_; INPUTS] = ["", "password", "setup arrange elevator foam jelly word wire either other oblige cupboard almost", "jellyfish"];

	// create inputs
	let inputs = data.map(|input| {
		let mut target = [0u8; SHA512_MAX_INPUT_SIZE];
		let source = input.as_bytes();

		target[..source.len()].copy_from_slice(source);

		Input {
			data: target.map(|b| b as u32),
			len: source.len() as u32,
		}
	});

	// create device
	let (device, queue) = pollster::block_on(device::init());

	// prepare layout descriptor
	let inputs_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
		label: Some("test-sha512::inputs"),
		contents: bytemuck::cast_slice(&inputs),
		usage: wgpu::BufferUsages::STORAGE,
	});

	let output_buffer = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("test-sha512::output"),
		size: (std::mem::size_of::<[u32; SHA512_HASH_LENGTH]>() * INPUTS) as u64,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// init shader
	let sources = ["src/shaders/sha512.wgsl", "src/shaders/pbkdf2.wgsl", "src/tests/test_pbkdf2.wgsl"];
	let source = sources.into_iter().fold(String::new(), |acc, nxt| acc + "\n" + &std::fs::read_to_string(nxt).unwrap());

	let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
		label: Some("test_sha512_main"),
		source: wgpu::ShaderSource::Wgsl(source.into()),
	});

	// configure bind group layout
	let descriptor = wgpu::BindGroupLayoutDescriptor {
		label: Some("test-sha512::bind-group-layout"),
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
		label: Some("test-sha512::bind_group"),
		layout: &bind_group_layout,
		entries: &[
			wgpu::BindGroupEntry {
				binding: 0,
				resource: inputs_buffer.as_entire_binding(),
			},
			wgpu::BindGroupEntry {
				binding: 1,
				resource: output_buffer.as_entire_binding(),
			},
		],
	});

	// configure pipeline layout
	let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
		label: Some("test-sha512::pipeline-layout"),
		bind_group_layouts: &[&bind_group_layout],
		push_constant_ranges: &[],
	});

	// create compute pipeline
	let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
		label: Some("test-sha512::pipeline"),
		module: &shader,
		entry_point: Some("main"),
		layout: Some(&pipeline_layout),
		// defaults
		cache: None,
		compilation_options: Default::default(),
	});

	// create command encoder
	let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("solver::encoder") });

	{
		// queue dispatch commands
		let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
			label: Some("test-sha512::pass"),
			timestamp_writes: None,
		});

		pass.set_pipeline(&pipeline);
		pass.set_bind_group(0, &bind_group, &[]);

		// calculate dimensions of dispatch
		pass.dispatch_workgroups(INPUTS as _, 1, 1);
	}

	// submit commands
	let commands = encoder.finish();
	let then = std::time::Instant::now();
	queue.submit([commands]);

	// wait for tasks to finish
	device.poll(wgpu::PollType::Wait).unwrap();
	let elapsed = then.elapsed();
	println!("PBKDF2 Hashing took: {:?}", elapsed / inputs.len() as u32);

	// read outputs buffer
	output_buffer.clone().map_async(wgpu::MapMode::Read, .., move |res| {
		res.unwrap();

		let view = output_buffer.get_mapped_range(..);
		let cast: &[[u32; SHA512_HASH_LENGTH]] = bytemuck::cast_slice(view.as_ref());

		for (idx, hash) in cast.iter().enumerate() {
			let gpu_output = hash.map(|s| s as u8);
			let cpu_output = pbkdf2(data[idx].as_bytes());

			assert_eq!(gpu_output, cpu_output, "HMAC Mismatch Between GPU and CPU",);
		}
	});

	// wait for tasks to finish
	device.poll(wgpu::PollType::Wait).unwrap();
}
