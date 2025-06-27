use std::fmt::Debug;

pub(crate) fn log_buffer<T: bytemuck::Pod + Debug>(device: &wgpu::Device, buffer: &wgpu::Buffer, label: &'static str, count: usize) {
	let buffer_ = buffer.clone();

	buffer.map_async(wgpu::MapMode::Read, .., move |res| {
		res.unwrap();

		let range = buffer_.get_mapped_range(..);
		let data: &[T] = bytemuck::cast_slice(range.as_ref());

		for (idx, i) in data.iter().take(count).enumerate() {
			println!("{}[{}] = {:?}", label, idx, i);
		}

		drop(range);
		buffer_.unmap();
	});

	device.poll(wgpu::PollType::Wait).unwrap();
}
