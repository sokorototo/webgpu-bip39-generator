use std::{mem, sync, time};

pub(crate) mod passes;
pub(crate) mod types;
pub(crate) mod utils;

use passes::*;

// 2 ^ 24 = 16777216
pub(crate) const THREADS_PER_DISPATCH: u32 = 16777216; // WORKGROUP_SIZE * DISPATCH_SIZE_X * DISPATCH_SIZE_Y

// 6.25% chance of finding a match ~ 1398101
pub(crate) const MAX_RESULTS_FOUND: usize = (THREADS_PER_DISPATCH as usize) / 12;

// flags to enable sending certain data through the sender
pub(crate) const MATCHES_READ_FLAG: u8 = 0b0000_0001;
pub(crate) const HASHES_READ_FLAG: u8 = 0b0000_0010;

// represents data extracted from the solver
pub(crate) struct SolverUpdate {
	pub(crate) step: u64,
	pub(crate) data: SolverData,
}

#[allow(unused)]
pub(crate) enum SolverData {
	Matches {
		constants: passes::filter::PushConstants,
		matches: Box<[types::Word2]>,
	},
	Hashes {
		constants: passes::derivation::PushConstants,
		hashes: Box<[types::GpuSha512Hash]>,
	},
}

#[allow(unused)]
pub(crate) fn solve<const F: u8>(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue, sender: sync::mpsc::Sender<SolverUpdate>) {
	// initialize destination buffers
	let matches_dest = (F & MATCHES_READ_FLAG == MATCHES_READ_FLAG).then(|| {
		device.create_buffer(&wgpu::BufferDescriptor {
			label: Some("solver_matches_destination"),
			size: (mem::size_of::<[types::Word2; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
			mapped_at_creation: false,
		})
	});

	let hashes_dest = (F & HASHES_READ_FLAG == HASHES_READ_FLAG).then(|| {
		device.create_buffer(&wgpu::BufferDescriptor {
			label: Some("solver_hashes_destination"),
			size: (mem::size_of::<[types::GpuSha512Hash; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
			mapped_at_creation: false,
		})
	});

	// initialize passes
	let mut filter_pass = filter::FilterPass::new(device, config.stencil.iter().map(|s| s.as_str()));
	let reset_pass = reset::ResetPass::new(device, &filter_pass);
	let mut derivation_pass = derivation::DerivationPass::new(device, &filter_pass);

	log::info!("Initialized Compute Passes");

	// track time taken per iteration
	let mut then = time::Instant::now();

	// each pass steps by THREADS_PER_DISPATCH = 2^24
	// MAX(config.range.1) = 2^44. THREADS_PER_DISPATCH * 2^22
	for step in (config.range.0..config.range.1).step_by(THREADS_PER_DISPATCH as _) {
		// 0: update push constants
		let entropy = (step / THREADS_PER_DISPATCH as u64) as u32;
		let word1 = (filter_pass.constants.words[1] & 0xfff00000) | entropy;

		filter_pass.constants.words[1] = word1;
		derivation_pass.constants.words[1] = word1;

		// 1: queue compute work
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("compute_work") });

		{
			// queue reset pass
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("reset_pass"),
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
				label: Some("filter_pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&filter_pass.pipeline);
			pass.set_push_constants(0, bytemuck::cast_slice(&[filter_pass.constants]));
			pass.set_bind_group(0, &filter_pass.bind_group, &[]);

			// calculate dimensions of dispatch
			let threads = (config.range.1 - step).min(THREADS_PER_DISPATCH as _);
			let dispatch = ((threads as u32 + filter::FilterPass::WORKGROUP_SIZE - 1) / filter::FilterPass::WORKGROUP_SIZE).max(1);

			pass.dispatch_workgroups(filter::FilterPass::DISPATCH_SIZE_X.min(dispatch), (dispatch / filter::FilterPass::DISPATCH_SIZE_Y).max(1), 1);
		}

		// queue derivation pass, if results are needed
		if (F & HASHES_READ_FLAG == HASHES_READ_FLAG) {
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("derivation_pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&derivation_pass.pipeline);
			pass.set_push_constants(0, bytemuck::cast_slice(&[derivation_pass.constants]));
			pass.set_bind_group(0, &derivation_pass.bind_group, &[]);

			// dispatch workgroups for exact results produced by filter pass
			pass.dispatch_workgroups_indirect(&filter_pass.dispatch_buffer, 0);
		}

		// submit
		queue.submit([encoder.finish()]);
		device.poll(wgpu::PollType::Wait).unwrap();

		// 2: copy results buffers to staging buffers
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("copy_work") });

		// queue read results from filter pass
		if let Some(dest) = matches_dest.as_ref() {
			encoder.copy_buffer_to_buffer(&filter_pass.matches_buffer, 0, &dest, 0, (mem::size_of::<[types::Word2; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress);
		};

		// queue read results from derivation pass
		if let Some(dest) = hashes_dest.as_ref() {
			encoder.copy_buffer_to_buffer(
				&derivation_pass.output_buffer,
				0,
				&dest,
				0,
				(mem::size_of::<[types::GpuSha512Hash; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			);
		};

		// submit
		queue.submit([encoder.finish()]);
		device.poll(wgpu::PollType::Wait).unwrap();

		log::info!("Executed {} threads in {:?}", (config.range.1 - step).min(THREADS_PER_DISPATCH as _), then.elapsed());

		// 3: send copies of compute work over sender
		let mut matches_count = 0;

		if (F & MATCHES_READ_FLAG == MATCHES_READ_FLAG) || (F & HASHES_READ_FLAG == HASHES_READ_FLAG) {
			let (count_send, count_recv) = sync::mpsc::sync_channel(1);
			let _count_buffer = filter_pass.count_buffer.clone();

			// read count buffer
			filter_pass.count_buffer.map_async(wgpu::MapMode::Read, .., move |res| match res {
				Ok(_) => {
					let range = _count_buffer.get_mapped_range(..);
					let bytes: &[u32] = bytemuck::cast_slice(range.as_ref());

					count_send.send(bytes[0]).unwrap();

					drop(range);
					_count_buffer.unmap();
				}
				Err(err) => {
					log::error!("Unable to reset count buffer: {}", err);
				}
			});

			// poll map_async callback
			device.poll(wgpu::PollType::Wait).unwrap();
			matches_count = count_recv.recv_timeout(time::Duration::from_secs(5)).expect("Unable to acquire matches_count from buffer");

			log::debug!("Valid Mnemonic Phrases Found: {}", matches_count);

			// output buffer was full
			if matches_count >= MAX_RESULTS_FOUND as _ {
				panic!("More than {} results found: {}", MAX_RESULTS_FOUND, matches_count);
			}
		}

		// send entropies if requested
		if let Some(matches_dest) = matches_dest.as_ref() {
			log::debug!("Mapping `Matches` destination buffer");

			// map results_destination
			let matches_dest_ = matches_dest.clone();
			let sender_ = sender.clone();

			matches_dest.map_async(wgpu::MapMode::Read, .., move |res| {
				res.unwrap();

				let mut range = matches_dest_.get_mapped_range(..);
				let results: &[types::Word2] = bytemuck::cast_slice(range.as_ref());

				// send results
				sender_
					.send(SolverUpdate {
						step,
						data: SolverData::Matches {
							constants: filter_pass.constants,
							matches: Box::from(&results[..matches_count as _]),
						},
					})
					.expect("Unable to send results through channel");

				drop(range);
				matches_dest_.unmap();
			});

			// poll map_async callback
			device.poll(wgpu::PollType::Wait).unwrap();
		}

		// send hashes if requested
		if let Some(hashes_dest) = hashes_dest.as_ref() {
			log::debug!("Mapping `Hashes` destination buffer");

			// map results_destination
			let hashes_dest_ = hashes_dest.clone();
			let sender_ = sender.clone();

			hashes_dest.map_async(wgpu::MapMode::Read, .., move |res| {
				res.unwrap();

				let mut range = hashes_dest_.get_mapped_range(..);
				let results: &[types::GpuSha512Hash] = bytemuck::cast_slice(range.as_ref());

				// send results
				sender_
					.send(SolverUpdate {
						step,
						data: SolverData::Hashes {
							constants: derivation_pass.constants,
							hashes: Box::from(&results[..matches_count as _]),
						},
					})
					.expect("Unable to send results through channel");

				drop(range);
				hashes_dest_.unmap();
			});

			// poll map_async callback
			device.poll(wgpu::PollType::Wait).unwrap();
		}

		// update time tracker
		then = time::Instant::now();
	}
}
