use std::sync;

pub(crate) mod passes;
pub(crate) mod types;

use passes::*;

// 2 ^ 24 = 16777216
pub(crate) const THREADS_PER_DISPATCH: u32 = 16777216; // WORKGROUP_SIZE * DISPATCH_SIZE_X * DISPATCH_SIZE_Y

// 30% chance of finding a match ~ 524288
pub(crate) const MAX_RESULTS_FOUND: usize = (THREADS_PER_DISPATCH as usize) / (std::mem::size_of::<types::Entropy>() * 2);

pub(crate) fn stencil_to_constants<'a, I: Iterator<Item = &'a str>>(words: I) -> types::PushConstants {
	// map stencil to mnemonic
	let replaced = words.map(|s| if s == "_" { "abandon" } else { s }).collect::<Vec<_>>().join(" ");
	let mnemonic = bip39::Mnemonic::parse_in_normalized_without_checksum_check(bip39::Language::English, &replaced).unwrap();

	let entropy = mnemonic.to_entropy();
	let slice: &[u32] = bytemuck::cast_slice(&entropy);

	// mnemonic is bigEndian: 💀
	let mut words = [0u32; 4];
	words.copy_from_slice(slice);
	words = words.map(|w| w.to_be());

	types::PushConstants {
		words,
		checksum: mnemonic.checksum() as _,
		entropy: 0,
	}
}

#[allow(unused)]
pub(crate) fn solve<F: FnMut(u64, &types::PushConstants, &[types::Entropy]) + Send + Sync + 'static>(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue, callback: F) {
	// initialize state
	let callback = sync::Arc::new(sync::Mutex::new(callback));
	let mut constants = stencil_to_constants(config.stencil.iter().map(|s| s.as_str()));

	// initialize passes
	let filter_pass = filter::FilterPass::new(device);
	let reset_pass = reset::ResetPass::new(device, &filter_pass);

	// init buffers
	let entropies_destination = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("solver::results-destination"),
		size: (std::mem::size_of::<[types::P2PKH_Address; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// each pass steps by THREADS_PER_DISPATCH
	// MAX(config.range.1) = 2^44, maps to 2^24
	for step in (config.range.0..config.range.1).step_by(THREADS_PER_DISPATCH as _) {
		// compress entropy from 2^44 to 2^24. Each dispatch processes 2^24 threads
		constants.entropy = (step / THREADS_PER_DISPATCH as u64) as _;

		// queue commands to find 3rd word
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("solver::encoder") });

		{
			// queue reset pass
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("reset::pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&reset_pass.pipeline);
			pass.set_bind_group(0, &reset_pass.bind_group, &[]);

			// dispatch
			pass.dispatch_workgroups(reset::ResetPass::DISPATCH_SIZE_X, reset::ResetPass::DISPATCH_SIZE_Y, 1);
		}

		{
			// queue filter pass
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("filter::pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&filter_pass.pipeline);
			pass.set_bind_group(0, &filter_pass.bind_group, &[]);
			pass.set_push_constants(0, bytemuck::cast_slice(&[constants]));

			// calculate dimensions of dispatch
			let threads = (config.range.1 - step).min(THREADS_PER_DISPATCH as _);
			let dispatch = ((threads as u32 + filter::FilterPass::WORKGROUP_SIZE - 1) / filter::FilterPass::WORKGROUP_SIZE).max(1);

			pass.dispatch_workgroups(filter::FilterPass::DISPATCH_SIZE_X.min(dispatch), (dispatch / filter::FilterPass::DISPATCH_SIZE_Y).max(1), 1);
		}

		// TODO: insert secondary pass here, use dispatch_indirect to avoid CPU sync of counter and output entropies

		{
			// queue read results from derivation pass
			encoder.copy_buffer_to_buffer(
				&filter_pass.entropies_buffer,
				0,
				&entropies_destination,
				0,
				(std::mem::size_of::<[types::Entropy; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			);
		}

		// submit commands
		let commands = encoder.finish();
		queue.submit([commands]);

		// wait for results_destination to be ready
		let (count_send, count_recv) = sync::mpsc::sync_channel(1);
		let _count_buffer = filter_pass.count_buffer.clone();

		// reset count buffer
		filter_pass.count_buffer.map_async(wgpu::MapMode::Read, .., move |res| match res {
			Ok(_) => {
				let range = _count_buffer.get_mapped_range(..);
				let bytes: &[u32] = bytemuck::cast_slice(range.as_ref());

				count_send.send(bytes[0]).unwrap();

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
		let count = count_recv.recv().expect("Unable to acquire count from buffer");

		if count >= MAX_RESULTS_FOUND as _ {
			panic!("More than {} results found: {}", MAX_RESULTS_FOUND, count);
		}

		// map results_destination
		let _results_destination = entropies_destination.clone();
		let _callback = callback.clone();

		entropies_destination.map_async(wgpu::MapMode::Read, .., move |res| {
			let mut range = _results_destination.get_mapped_range(..);
			let results: &[types::Entropy] = bytemuck::cast_slice(range.as_ref());

			// call callback
			let mut c = _callback.lock().unwrap();
			c(step, &constants, &results[..(count as usize)]);

			drop(range);
			_results_destination.unmap();
		});

		// wait for callback to finish
		device.poll(wgpu::PollType::Wait).unwrap();
	}
}
