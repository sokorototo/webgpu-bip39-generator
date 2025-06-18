use sha256_rs::sha256;

pub(crate) mod pipeline;
pub(crate) mod types;

pub(crate) const WORKGROUP_SIZE: u32 = 64; // 2 ^ 6
pub(crate) const DISPATCH_SIZE: u32 = 65536; // 2 ^ 16
pub(crate) const THREADS_PER_DISPATCH: u32 = WORKGROUP_SIZE * DISPATCH_SIZE; // 2 ^ 22 = 4194304

pub(crate) const MAX_RESULTS_FOUND: usize = 65536; // ≈ 2 ^ 16

pub(crate) fn map_stencil_to_words<'a, I: Iterator<Item = &'a str>>(words: I) -> [types::Word; 4] {
	assert_eq!(words.size_hint().0, 12, "Only 12 word mnemonics are supported");
	let mut out: [types::Word; 4] = bytemuck::Zeroable::zeroed();

	// map stencil to mnemonic
	let replaced = words.map(|s| if s == "_" { "abandon" } else { s }).collect::<Vec<_>>().join(" ");
	let replaced = replaced.to_lowercase();

	let mnemonic = bip39::Mnemonic::parse_in_normalized_without_checksum_check(bip39::Language::English, &replaced).unwrap();

	let (entropy, len) = mnemonic.to_entropy_array();
	assert_eq!(len, 16, "Only 12 word mnemonics are supported");

	for (idx, bytes) in entropy.chunks_exact(4).take(len / 4).enumerate() {
		let mut buf = [0u8; 4];
		buf.copy_from_slice(bytes);
		out[idx].bits = u32::from_le_bytes(buf);
	}

	let shifted = mnemonic.checksum() >> 4;
	for i in 0..=3 {
		out[i].checksum = (shifted & (1 << i)) as u32;
	}

	out
}

// check sha256 bit on word with index
pub(crate) fn verify_word(word: &types::Word, idx: usize) -> bool {
	let bytes = word.bits.to_le_bytes();
	let hash_bit = sha256(&bytes)[0] & 0b1;
	((hash_bit >> idx) & word.checksum as u8) == word.checksum as u8
}

#[allow(unused)]
/// 2nd and 3rd words are unknown
pub(crate) fn solve(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue) {
	// initialize pipeline
	let words = map_stencil_to_words(config.stencil.iter().map(|s| s.as_str()));
	let (pipeline, bind_group, results_source, count_source) = pipeline::create(device, &words);

	// init destination buffer
	let results_destination = device.create_buffer(&wgpu::BufferDescriptor {
		label: Some("solver::results-destination"),
		size: (std::mem::size_of::<[types::Word; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress,
		usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
		mapped_at_creation: false,
	});

	// verify 2nd word on CPU, if passes search for 3rd word on GPU
	for entropy in (config.range.0..=config.range.1).rev().step_by(THREADS_PER_DISPATCH as _) {
		// each pass steps by 4194304 = 2 ^ 22
		// each pass has a workgroup size of 64 = 2 ^ 6
		// workgroups are dispatched in (65536, 1, 1) = 2 ^ 16
		let remaining = (entropy.saturating_sub(config.range.0)).min(DISPATCH_SIZE as _);

		// combine entropy for word 2, check and filter
		let mut words = words.clone();

		let word_2 = &mut words[1];
		word_2.bits |= entropy as u32;

		if !verify_word(word_2, 1) {
			continue;
		}

		// queue commands to find 3rd word
		let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("solver::encoder") });

		{
			// queue dispatch commands
			let descriptor = wgpu::ComputePassDescriptor {
				label: Some("solver::pass"),
				timestamp_writes: None,
			};

			let mut pass = encoder.begin_compute_pass(&descriptor);

			pass.set_pipeline(&pipeline);
			pass.set_bind_group(0, &bind_group, &[]);
			pass.set_push_constants(0, bytemuck::cast_slice(&words));
			pass.dispatch_workgroups(remaining as _, 1, 1);
		}

		{
			// queue copy commands
			encoder.copy_buffer_to_buffer(&results_source, 0, &results_destination, 0, (std::mem::size_of::<[types::Word; MAX_RESULTS_FOUND]>()) as wgpu::BufferAddress);
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
			}
			Err(err) => {
				eprintln!("Unable to reset count buffer: {}", err);
			}
		});

		count_source.unmap();

		// read results_dest buffer
		let r_clone = results_destination.clone();

		results_destination.map_async(wgpu::MapMode::Read, .., move |res| match c_recv.recv() {
			Ok(count) => {
				let mut range = r_clone.get_mapped_range(..);

				let results: &[types::Word] = bytemuck::cast_slice(range.as_ref());

				for res in results {
					let mut words = words.clone();
					words[2] = *res;

					println!("Found Words: {:?}", words);
				}
			}
			Err(err) => {
				eprintln!("Unable to acquire count from buffer: {}", err);
			}
		});

		results_destination.unmap();
	}
}
