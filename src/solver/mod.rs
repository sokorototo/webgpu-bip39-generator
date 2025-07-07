use std::{mem, time};

pub(crate) mod passes;
pub(crate) mod types;
pub(crate) mod utils;

use passes::*;

// 2 ^ 24 = 16777216
pub(crate) const STEP: u32 = 16777216; // WORKGROUP_SIZE * DISPATCH_SIZE_X * DISPATCH_SIZE_Y

// 6.25% chance of finding a match ~ 1398101
pub(crate) const MAX_RESULTS_FOUND: usize = (STEP as usize) / 12;

// represents data extracted from the solver
pub(crate) struct StageComputation {
	pub(crate) step: u64,
	pub(crate) constants: passes::derivation::PushConstants,
	pub(crate) outputs: Box<[types::DerivationsOutput]>,
}

#[allow(unused)]
pub(crate) fn solve(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue, sender: flume::Sender<StageComputation>) {
	// initialize passes
	let mut filter_pass = filter::FilterPass::new(device, config.stencil.iter().map(|s| s.as_str()));
	let reset_pass = reset::ResetPass::new(device, &filter_pass);
	let mut derivation_pass = derivation::DerivationPass::new(device, &filter_pass);

	// track time taken per iteration
	let mut then: Option<time::Instant> = None;

	// each pass steps by STEP = 2^24
	// MAX(config.range.1) = 2^44. STEP * 2^22
	for step in (config.range.0..config.range.1).step_by(STEP as _) {
		// track time per iteration
		#[cfg(debug_assertions)]
		match then.as_mut() {
			Some(p) => {
				let now = time::Instant::now();
				log::debug!("GPU Compute Passes took: {:?}", p.elapsed());
				*p = now;
			}
			None => then = Some(time::Instant::now()),
		};

		// 0: update push constants
		let entropy = (step / STEP as u64) as u32;
		let word1 = (filter_pass.constants.words[1] & 0xfff00000) | entropy;

		filter_pass.constants.words[1] = word1;
		derivation_pass.constants.word1 = word1;

		// 1: queue reset and filter pass
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("filter_pass") });

		{
			log::debug!("Queueing Reset Pass");

			// queue: reset pass
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("reset_pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&reset_pass.pipeline);
			pass.set_bind_group(0, &reset_pass.bind_group, &[]);
			pass.dispatch_workgroups(reset::ResetPass::DISPATCH_SIZE_X, reset::ResetPass::DISPATCH_SIZE_Y, 1);
		}

		{
			log::debug!("Queueing Filter Pass");

			// queue: filter pass
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("filter_pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&filter_pass.pipeline);
			pass.set_push_constants(0, bytemuck::cast_slice(&[filter_pass.constants]));
			pass.set_bind_group(0, &filter_pass.bind_group, &[]);

			// calculate dimensions of dispatch
			let threads = (config.range.1 - step).min(STEP as _);
			let dispatch = ((threads as u32 + filter::FilterPass::WORKGROUP_SIZE - 1) / filter::FilterPass::WORKGROUP_SIZE);

			let dispatch_x = filter::FilterPass::DISPATCH_SIZE_X.min(dispatch);
			let dispatch_y = (dispatch / filter::FilterPass::DISPATCH_SIZE_Y).max(1);

			log::debug!(target: "solver::filter_stage", "Threads = {}, DispatchX = {}, DispatchY = {}, WorkgroupSize = {}", threads, dispatch_x, dispatch_y, filter::FilterPass::WORKGROUP_SIZE);
			pass.dispatch_workgroups(dispatch_x, dispatch_y, 1);
		}

		// submit
		queue.submit([encoder.finish()]);
		device.poll(wgpu::PollType::Wait).unwrap();

		// 2: read X matches produced by filter stage
		let mut matches_count = {
			let (count_send, count_recv) = flume::bounded(1);
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
			let count = count_recv.recv_timeout(time::Duration::from_secs(5)).expect("Unable to acquire matches_count from buffer");

			log::debug!(target: "solver::filter_stage", "Valid Mnemonic Phrases Found: {}", count);

			// output buffer was full
			if count >= MAX_RESULTS_FOUND as _ {
				panic!("More than {} results found: {}", MAX_RESULTS_FOUND, count);
			};

			count
		};

		// 3: queue derivations passes
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("derivations_pass") });

		{
			// queue: derivation pass
			log::debug!("Queueing Derivation Pass and Dispatches");

			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("derivation_pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&derivation_pass.pipeline);
			pass.set_bind_group(0, &derivation_pass.bind_group, &[]);

			// call derivations pass in smaller dispatches to avoid GPU timeouts
			let mut constants = derivation_pass.constants;
			constants.count = matches_count;

			let threads_per_iteration = config.threads.unwrap_or(128) * derivation::DerivationPass::WORKGROUP_SIZE;
			log::debug!(target: "solver::derivations_stage", "Inputs = {}, Dispatches = {}, WorkgroupSize = {}", matches_count, (matches_count + threads_per_iteration - 1) / threads_per_iteration, derivation::DerivationPass::WORKGROUP_SIZE);

			loop {
				// prepare dispatch
				let threads = (matches_count - constants.offset).min(threads_per_iteration);
				let dispatch_x = (threads + derivation::DerivationPass::WORKGROUP_SIZE - 1) / derivation::DerivationPass::WORKGROUP_SIZE;

				log::debug!(target: "solver::derivations_stage", "Remaining = {}, DispatchX = {}", matches_count - constants.offset, dispatch_x);
				pass.set_push_constants(0, bytemuck::cast_slice(&[constants]));
				pass.dispatch_workgroups(dispatch_x, 1, 1);

				// are we done?
				constants.offset = constants.offset.saturating_add(threads);
				if constants.offset >= matches_count {
					break;
				}
			}
		}

		// submit
		queue.submit([encoder.finish()]);
		device.poll(wgpu::PollType::Wait).unwrap();

		{
			// 4: send copies of compute work over sender
			let hashes_src_ = derivation_pass.output_buffer.clone();
			let sender_ = sender.clone();

			derivation_pass.output_buffer.map_async(wgpu::MapMode::Read, .., move |res| {
				res.unwrap();

				let mut range = hashes_src_.get_mapped_range(..);
				let results: &[types::DerivationsOutput] = bytemuck::cast_slice(range.as_ref());

				let output = StageComputation {
					step,
					constants: derivation_pass.constants,
					outputs: Box::from(&results[..matches_count as _]),
				};

				// send results
				sender_.send(output).expect("Unable to send results through channel");

				drop(range);
				hashes_src_.unmap();
			});

			// poll map_async callback
			device.poll(wgpu::PollType::Wait).unwrap();
		}
	}
}
