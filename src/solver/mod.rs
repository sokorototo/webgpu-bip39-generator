use std::sync;

pub(crate) mod pipeline;
pub(crate) mod types;

pub(crate) const WORKGROUP_SIZE: u32 = 64; // 2 ^ 6
pub(crate) const DISPATCH_SIZE_X: u32 = 256; // 2 ^ 8
pub(crate) const DISPATCH_SIZE_Y: u32 = 256; // 2 ^ 8

// 2 ^ 22 = 4194304
pub(crate) const THREADS_PER_DISPATCH: u32 = WORKGROUP_SIZE * DISPATCH_SIZE_X * DISPATCH_SIZE_Y;

pub(crate) const MAX_RESULTS_FOUND: usize = 65536; // ≈ 2 ^ 16

pub(crate) fn stencil_to_constants<'a, I: Iterator<Item = &'a str>>(words: I) -> types::PushConstants {
	// map stencil to mnemonic
	let replaced = words.map(|s| if s == "_" { "abandon" } else { s }).collect::<Vec<_>>().join(" ");
	let mnemonic = bip39::Mnemonic::parse_in_normalized_without_checksum_check(bip39::Language::English, &replaced).unwrap();

	let entropy = mnemonic.to_entropy();
	let slice: &[u32] = bytemuck::cast_slice(&entropy);

	let mut words = [0u32; 4];
	words.copy_from_slice(slice);

	types::PushConstants {
		words,
		checksum: mnemonic.checksum() as _,
		entropy: 0,
	}
}

#[allow(unused)]
pub(crate) fn solve<F: Fn(&types::PushConstants, &[types::P2PKH_Address]) + Send + Sync + 'static>(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue, callback: F) {
	// initialize callback
	let callback = sync::Arc::new(callback);

	// initialize pipeline
	let mut constants = stencil_to_constants(config.stencil.iter().map(|s| s.as_str()));
	let pipeline::State {
		pipeline,
		bind_group,
		results_source,
		count_buffer,
		target_buffer,
	} = pipeline::create(device, config);

	// init buffers
	let results_destination = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("solver::results-destination"),
		size: (std::mem::size_of::<[types::P2PKH_Address; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// each pass steps by THREADS_PER_DISPATCH
	// MAX(config.range.1) = 2^44, maps to 2^22
	for step in (config.range.0..config.range.1).step_by(THREADS_PER_DISPATCH as _) {
		// compress entropy from 2^44 to 2^22. Each dispatch processes 2^22 threads
		constants.entropy = ((step / THREADS_PER_DISPATCH as u64) << 10) as _;

		// queue commands to find 3rd word
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("solver::encoder") });

		{
			// queue dispatch commands
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("solver::pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&pipeline);
			pass.set_bind_group(0, &bind_group, &[]);
			pass.set_push_constants(0, bytemuck::cast_slice(&[constants]));

			// calculate dimensions of dispatch
			let threads = (config.range.1 - step).min(THREADS_PER_DISPATCH as _);
			let dispatch = (threads / WORKGROUP_SIZE as u64).max(1) as u32;

			pass.dispatch_workgroups(DISPATCH_SIZE_X.min(dispatch), (dispatch / DISPATCH_SIZE_Y).max(1), 1);
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
		let (count_send, count_recv) = sync::mpsc::sync_channel(1);
		let _count_buffer = count_buffer.clone();

		// reset count buffer
		count_buffer.map_async(wgpu::MapMode::Write, .., move |res| match res {
			Ok(_) => {
				let mut range = _count_buffer.get_mapped_range_mut(..);
				let bytes: &mut [u32] = bytemuck::cast_slice_mut(range.as_mut());

				count_send.send(bytes[0]).unwrap();
				bytes[0] = 0;

				drop(range);
				_count_buffer.unmap();
			}
			Err(err) => {
				eprintln!("Unable to reset count buffer: {}", err);
			}
		});

		// poll event loop
		device.poll(wgpu::PollType::Wait).unwrap();

		// read results_destination copy buffer
		match count_recv.recv() {
			Ok(count) => {
				if count == 0 {
					continue;
				}

				// TODO: insert secondary pass here, use dispatch_indirect to avoid CPU sync of counter

				if count >= MAX_RESULTS_FOUND as _ {
					panic!("More than {} results found", MAX_RESULTS_FOUND);
				}

				// map results_destination
				let _results_destination = results_destination.clone();
				let _callback = callback.clone();

				results_destination.map_async(wgpu::MapMode::Read, .., move |res| {
					let mut range = _results_destination.get_mapped_range(..);

					let results: &[types::P2PKH_Address] = bytemuck::cast_slice(range.as_ref());
					_callback(&constants, &results[..count as _]);

					drop(range);
					_results_destination.unmap();
				});

				// wait for callback to finish
				device.poll(wgpu::PollType::Wait).unwrap();
			}
			Err(err) => {
				eprintln!("Unable to acquire count from buffer: {}", err);
			}
		}
	}
}
