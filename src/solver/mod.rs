use std::{
	sync::{self, mpsc},
	time,
};

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

pub(crate) enum SolverData {
	Matches {
		constants: passes::filter::PushConstants,
		matches: Box<[types::Word2]>,
	},
	Derivations {
		constants: passes::derivation::PushConstants,
		hashes: Box<[types::GpuSha512Hash]>,
	},
}

#[allow(unused)]
pub(crate) fn solve<const F: u8>(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue, sender: mpsc::Sender<SolverUpdate>) {
	// initialize destination buffers
	let matches_dest = (F & MATCHES_READ_FLAG == MATCHES_READ_FLAG).then(|| {
		device.create_buffer(&wgpu::BufferDescriptor {
			label: Some("solver_matches_destination"),
			size: (std::mem::size_of::<[types::Word2; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
			mapped_at_creation: false,
		})
	});

	// let hashes_dest = (F & HASHES_READ_FLAG == HASHES_READ_FLAG).then(|| {
	// 	device.create_buffer(&wgpu::BufferDescriptor {
	// 		label: Some("solver_hashes_destination"),
	// 		size: (std::mem::size_of::<[types::GpuSha512Hash; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
	// 		usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
	// 		mapped_at_creation: false,
	// 	})
	// });

	// initialize passes
	let mut filter_pass = filter::FilterPass::new(device, config.stencil.iter().map(|s| s.as_str()));
	let reset_pass = reset::ResetPass::new(device, &filter_pass);
	let derivation_pass = derivation::DerivationPass::new(device, &filter_pass, config.address);

	// each pass steps by THREADS_PER_DISPATCH = 2^24
	// MAX(config.range.1) = 2^44. THREADS_PER_DISPATCH * 2^22
	for step in (config.range.0..config.range.1).step_by(THREADS_PER_DISPATCH as _) {
		let mut matches_count = 0;
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("solver::encoder") });

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

			// compress entropy from 2^44 to 2^20. Each dispatch processes 2^24 threads
			let entropy = (step / THREADS_PER_DISPATCH as u64) as u32;
			filter_pass.constants.words[1] = (filter_pass.constants.words[1] & 0xfff00000) & entropy;

			pass.set_pipeline(&filter_pass.pipeline);
			pass.set_push_constants(0, bytemuck::cast_slice(&[filter_pass.constants]));
			pass.set_bind_group(0, &filter_pass.bind_group, &[]);

			// calculate dimensions of dispatch
			let threads = (config.range.1 - step).min(THREADS_PER_DISPATCH as _);
			let dispatch = ((threads as u32 + filter::FilterPass::WORKGROUP_SIZE - 1) / filter::FilterPass::WORKGROUP_SIZE).max(1);

			pass.dispatch_workgroups(filter::FilterPass::DISPATCH_SIZE_X.min(dispatch), (dispatch / filter::FilterPass::DISPATCH_SIZE_Y).max(1), 1);
		}

		// queue read results from filter pass
		if let Some(dest) = matches_dest.as_ref() {
			encoder.copy_buffer_to_buffer(&filter_pass.matches_buffer, 0, &dest, 0, (std::mem::size_of::<[types::Word2; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress);
		};

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

		// queue read results from derivation pass
		// if let Some(dest) = hashes_dest.as_ref() {
		// 	encoder.copy_buffer_to_buffer(&derivation_pass.output_buffer, 0, &dest, 0, (std::mem::size_of::<[types::Match; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress);
		// };

		// submit commands
		let commands = encoder.finish();
		queue.submit([commands]);

		// wait for commands to finish
		device.poll(wgpu::PollType::Wait).unwrap();

		// if any read flags are set, read `count` buffer
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
					eprintln!("Unable to reset count buffer: {}", err);
				}
			});

			// poll map_async callback
			device.poll(wgpu::PollType::Wait).unwrap();
			matches_count = count_recv.recv_timeout(time::Duration::from_secs(5)).expect("Unable to acquire matches_count from buffer");

			// output buffer was full
			if matches_count >= MAX_RESULTS_FOUND as _ {
				panic!("More than {} results found: {}", MAX_RESULTS_FOUND, matches_count);
			}
		}

		// send entropies if requested
		if let Some(matches_dest) = matches_dest.as_ref() {
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
		if (F & HASHES_READ_FLAG == HASHES_READ_FLAG) {
			// map results_destination
			let hashes_src_ = derivation_pass.output_buffer.clone();
			let sender_ = sender.clone();

			derivation_pass.output_buffer.map_async(wgpu::MapMode::Read, .., move |res| {
				res.unwrap();

				let mut range = hashes_src_.get_mapped_range(..);
				let results: &[types::GpuSha512Hash] = bytemuck::cast_slice(range.as_ref());

				// send results
				sender_
					.send(SolverUpdate {
						step,
						data: SolverData::Derivations {
							constants: derivation_pass.constants,
							hashes: Box::from(&results[..matches_count as _]),
						},
					})
					.expect("Unable to send results through channel");

				drop(range);
				hashes_src_.unmap();
			});

			// poll map_async callback
			device.poll(wgpu::PollType::Wait).unwrap();
		}
	}
}
