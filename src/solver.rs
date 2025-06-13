use std::{io::Write, sync::mpsc, thread};

#[allow(unused)]
pub(crate) fn extract_seeds(config: &super::Config, device: &wgpu::Device, queue: &wgpu::Queue) -> u128 {
	let mut count = 0;
	let (sender, receiver) = mpsc::channel();

	// start log thread
	let handle = thread::spawn(move || {
		let mut output = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open("found.txt").unwrap();

		receiver.iter().for_each(|s| {
			let mut buffer = [0; (64 * 2) + 1];

			hex::encode_to_slice(s, &mut buffer[0..128]).unwrap();
			buffer[64 * 2] = '\n' as u8;

			output.write(buffer.as_slice()).unwrap();
		})
	});

	// start solver
	std::iter::repeat([245; 64]).take(64).for_each(move |s| {
		count += 1;
		sender.send(s).unwrap()
	});

	handle.join().unwrap();
	count
}
