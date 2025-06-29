use std::{sync, time};

pub(crate) mod passes;
pub(crate) mod types;
pub(crate) mod utils;

use passes::*;

// 2 ^ 24 = 16777216
pub(crate) const THREADS_PER_DISPATCH: u32 = 16777216; // WORKGROUP_SIZE * DISPATCH_SIZE_X * DISPATCH_SIZE_Y

// 30% chance of finding a match ~ 2097152
pub(crate) const MAX_RESULTS_FOUND: usize = (THREADS_PER_DISPATCH as usize) / 4;

pub(crate) struct EntropyCallback<F = EntropyCallbackDefault>(pub(crate) F);
pub(crate) type EntropyCallbackDefault = fn(u64, &filter::PushConstants, &[types::Entropy]);

#[allow(unused)]
pub(crate) fn solve<E>(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue, entropies_callback: Option<EntropyCallback<E>>)
where
	E: FnMut(u64, &filter::PushConstants, &[types::Entropy]) + Send + Sync + 'static,
{
	// initialize state
	let entropies_callback = entropies_callback.map(|e| sync::Arc::new(sync::Mutex::new(e)));
	let entropies_callback_state = entropies_callback.map(|e| {
		let entropies_dest = device.create_buffer(&wgpu::BufferDescriptor {
			label: Some("solver_entropies_destination"),
			size: (std::mem::size_of::<[types::Entropy; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
			mapped_at_creation: false,
		});

		(entropies_dest, e)
	});

	// initialize passes
	let mut filter_pass = filter::FilterPass::new(device, config.stencil.iter().map(|s| s.as_str()));
	let reset_pass = reset::ResetPass::new(device, &filter_pass);
	let derivation_pass = derivation::DerivationPass::new(device, &filter_pass, config.address);

	// each pass steps by THREADS_PER_DISPATCH = 2^24
	// MAX(config.range.1) = 2^44. THREADS_PER_DISPATCH * 2^22
	for step in (config.range.0..config.range.1).step_by(THREADS_PER_DISPATCH as _) {
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
			filter_pass.constants.entropy = (step / THREADS_PER_DISPATCH as u64) as _;

			pass.set_pipeline(&filter_pass.pipeline);
			pass.set_push_constants(0, bytemuck::cast_slice(&[filter_pass.constants]));
			pass.set_bind_group(0, &filter_pass.bind_group, &[]);

			// calculate dimensions of dispatch
			let threads = (config.range.1 - step).min(THREADS_PER_DISPATCH as _);
			let dispatch = ((threads as u32 + filter::FilterPass::WORKGROUP_SIZE - 1) / filter::FilterPass::WORKGROUP_SIZE).max(1);

			pass.dispatch_workgroups(filter::FilterPass::DISPATCH_SIZE_X.min(dispatch), (dispatch / filter::FilterPass::DISPATCH_SIZE_Y).max(1), 1);
		}

		// if callback is registered, copy results to destination buffer
		if let Some((entropies_dest, _)) = entropies_callback_state.as_ref() {
			// queue read results from derivation pass
			encoder.copy_buffer_to_buffer(
				&filter_pass.entropies_buffer,
				0,
				&entropies_dest,
				0,
				(std::mem::size_of::<[types::Entropy; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
			);
		};

		{
			// queue derivation pass
			let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
				label: Some("derivation_pass"),
				timestamp_writes: None,
			});

			pass.set_pipeline(&derivation_pass.pipeline);
			pass.set_push_constants(0, bytemuck::cast_slice(&[derivation_pass.constants]));
			pass.set_bind_group(0, &derivation_pass.bind_group, &[]);

			// dispatch workgroups for exact results produced by filter pass
			pass.dispatch_workgroups_indirect(&filter_pass.dispatch_buffer, 0);
			// pass.dispatch_workgroups(64, 1, 1);
		}

		// submit commands
		let commands = encoder.finish();
		queue.submit([commands]);

		// wait for commands to finish
		device.poll(wgpu::PollType::Wait).unwrap();

		// call callback if registered
		if let Some((entropies_dest, callback)) = entropies_callback_state.as_ref() {
			// wait for results_destination to be ready
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
			let count = count_recv.recv_timeout(time::Duration::from_secs(5)).expect("Unable to acquire count from buffer");

			// log buffers for debugging
			// utils::inspect_buffer(device, &derivation_pass.output_buffer, move |data: &[types::GpuSha512Hash]| {
			// 	println!("Buffer[derivation::output_buffer] = {}", count);
			// 	let zeroed: types::GpuSha512Hash = bytemuck::Zeroable::zeroed();

			// 	for (idx, i) in data.iter().take(count as _).enumerate() {
			// 		if i == &zeroed {
			// 			continue;
			// 		}

			// 		println!("[{}] = {:?}", idx, i);
			// 	}
			// });

			if count >= MAX_RESULTS_FOUND as _ {
				panic!("More than {} results found: {}", MAX_RESULTS_FOUND, count);
			}

			// map results_destination
			let entropies_dest_ = entropies_dest.clone();
			let callback_ = callback.clone();
			let constants_ = filter_pass.constants;

			entropies_dest.map_async(wgpu::MapMode::Read, .., move |res| {
				res.unwrap();

				let mut range = entropies_dest_.get_mapped_range(..);
				let results: &[types::Entropy] = bytemuck::cast_slice(range.as_ref());

				// call callback
				let mut c = callback_.lock().unwrap();
				c.0(step, &constants_, &results[..(count as usize)]);

				drop(range);
				entropies_dest_.unmap();
			});

			// poll map_async callback
			device.poll(wgpu::PollType::Wait).unwrap();
		}
	}
}
