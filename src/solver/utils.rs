use std::fmt::Debug;

pub(crate) fn inspect_buffer<T: bytemuck::Pod + Debug, F: Fn(&[T]) + Send + Sync + 'static>(device: &wgpu::Device, buffer: &wgpu::Buffer, callback: F) {
	let buffer_ = buffer.clone();
	buffer.map_async(wgpu::MapMode::Read, .., move |res| {
		res.unwrap();

		let range = buffer_.get_mapped_range(..);
		let data: &[T] = bytemuck::cast_slice(range.as_ref());

		// Call the provided callback with the data
		callback(data);

		drop(range);
		buffer_.unmap();
	});

	device.poll(wgpu::PollType::Wait).unwrap();
}
