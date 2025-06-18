pub(crate) mod pipeline;
pub(crate) mod types;

pub(crate) const WORKGROUP_SIZE: u32 = 64; // 2 ^ 6
pub(crate) const DISPATCH_SIZE: u32 = 65536; // 2 ^ 16
pub(crate) const THREADS_PER_DISPATCH: u32 = WORKGROUP_SIZE * DISPATCH_SIZE; // 2 ^ 22 = 4194304

pub(crate) const MAX_RESULTS_FOUND: usize = 65536; // ≈ 2 ^ 16

pub(crate) fn stencil_to_bytes<'a, I: Iterator<Item = &'a str>>(words: I) -> types::PushConstants {
	// map stencil to mnemonic
	let replaced = words.map(|s| if s == "_" { "abandon" } else { s }).collect::<Vec<_>>().join(" ");
	let mnemonic = bip39::Mnemonic::parse_in_normalized_without_checksum_check(bip39::Language::English, &replaced).unwrap();

	let entropy = mnemonic.to_entropy();
	let slice: &[u32] = bytemuck::cast_slice(&entropy);

	let mut words = [0u32; 4];
	words.copy_from_slice(slice);

	types::PushConstants {
		words,
		entropy: 0,
		checksum: mnemonic.checksum() as _,
	}
}

#[allow(unused)]
pub(crate) fn solve(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue) {
	// initialize pipeline
	let mut constants = stencil_to_bytes(config.stencil.iter().map(|s| s.as_str()));
	let pipeline::State {
		pipeline,
		bind_group,
		results_source,
		count_source,
		target_buffer,
	} = pipeline::create(device, config);

	// init buffers
	let results_destination = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("solver::results-destination"),
		size: (std::mem::size_of::<[types::P2PKH_Address; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// each pass steps by 4194304 = 2 ^ 22
	// each pass has a workgroup size of 64 = 2 ^ 6
	// workgroups are dispatched in (65536, 1, 1) = 2 ^ 16
	for entropy in (config.range.0..config.range.1).step_by(THREADS_PER_DISPATCH as _) {
		// compress entropy from 2^44 to 2^22. Each batch processes 2^22 combinations
		constants.entropy = (entropy / 2u64.pow(22)) as _;

		// queue commands to find 3rd word
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("solver::encoder") });

		{
			// queue dispatch commands
			let descriptor = wgpu::ComputePassDescriptor {
				label: Some("solver::pass"),
				timestamp_writes: None,
			};

			let mut pass = encoder.begin_compute_pass(&descriptor);
			let workload = (config.range.1 - entropy).min(DISPATCH_SIZE as _);

			pass.set_pipeline(&pipeline);
			pass.set_bind_group(0, &bind_group, &[]);
			pass.set_push_constants(0, bytemuck::cast_slice(&[constants]));
			pass.dispatch_workgroups(workload as _, 1, 1);
		}

		{
			// queue copy commands
			encoder.copy_buffer_to_buffer(
				&results_source,
				0,
				&results_destination,
				0,
				(std::mem::size_of::<[types::P2PKH_Address; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			);
		}

		// submit commands
		let commands = encoder.finish();
		queue.submit([commands]);

		// wait for results_destination to be ready
		let (send, c_recv) = oneshot::channel();
		let c_clone = count_source.clone();

		// reset count buffer
		count_source.map_async(wgpu::MapMode::Write, .., move |res| match res {
			Ok(_) => {
				let mut range = c_clone.get_mapped_range_mut(..);
				let results: &mut [u32] = bytemuck::cast_slice_mut(range.as_mut());

				send.send(results[0]).unwrap();
				results[0] = 0;

				drop(range);
				c_clone.unmap();
			}
			Err(err) => {
				eprintln!("Unable to reset count buffer: {}", err);
			}
		});

		// read results_dest buffer
		let r_clone = results_destination.clone();

		results_destination.map_async(wgpu::MapMode::Read, .., move |res| match c_recv.recv() {
			Ok(count) => {
				let mut range = r_clone.get_mapped_range(..);
				let results: &[types::P2PKH_Address] = bytemuck::cast_slice(range.as_ref());

				for res in results.iter().take(count as _) {
					dbg!(res);
				}

				drop(range);
				r_clone.unmap();
			}
			Err(err) => {
				eprintln!("Unable to acquire count from buffer: {}", err);
			}
		});

		// poll event loop
		device.poll(wgpu::PollType::Wait);
	}
}
