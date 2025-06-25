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
fn test_short256() {
	pub(crate) fn verify_results(constants: &solver::types::PushConstants, outputs: &[solver::types::P2PKH_Address]) {
		// verifies output from solver
		// let mut set = std::collections::BTreeSet::new();

		for output in outputs {
			// assert!(set.insert(output[0]), "Duplicate Entropy Found: {}", output[0]);
			// assert_eq!(constants.entropy, output[1], "Got Different Entropy from GPU");

			let input = [constants.words[0], output[0], output[1], constants.words[3]];
			let bytes: &[u8] = bytemuck::cast_slice(&input);

			let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, bytes).unwrap();
			assert_eq!(constants.checksum as u8, mnemonic.checksum(), "Extracted Mnemonic Sequence has invalid checksum");

			let shader_output = [output[2], output[3]].map(|s| s as u8);
			let expected = sha256(bytes);

			assert_eq!(&shader_output, &expected[..2], "Got Different Hash from Shader");
		}
	}

	// init devices
	let (device, queue) = pollster::block_on(device::init());

	let config = Config {
		stencil: ["elder", "resist", "rocket", "skill", "_", "_", "_", "_", "jungle", "return", "circle", "umbrella"]
			.map(|s| s.to_string())
			.into_iter()
			.collect(),
		range: (0, 2048),
		address: parse_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap(),
	};

	solver::solve(&config, &device, &queue, verify_results);
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
	let sources = ["src/shaders/sha512.wgsl", "src/shaders/pbkdf2.wgsl", "src/shaders/test_pbkdf2.wgsl"];
	let source = sources.into_iter().fold(String::new(), |acc, nxt| acc + "\n" + &std::fs::read_to_string(nxt).unwrap());

	let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
		label: Some("test-sha512::main"),
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
	queue.submit([commands]);

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
