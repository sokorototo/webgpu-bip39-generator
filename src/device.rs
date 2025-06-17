pub(crate) async fn init() -> (wgpu::Device, wgpu::Queue) {
	// configure wgpu
	let instance_desc = wgpu::InstanceDescriptor {
		backends: wgpu::Instance::enabled_backend_features(),
		..Default::default()
	};

	let adapter_options = wgpu::RequestAdapterOptions {
		power_preference: wgpu::PowerPreference::HighPerformance,
		..Default::default()
	};

	// initialize wgpu, and acquire adapter
	let instance = wgpu::Instance::new(&instance_desc);
	let adapter = instance.request_adapter(&adapter_options).await.unwrap();

	// acquire device and queue
	let device_options = wgpu::DeviceDescriptor {
		label: Some("mnemonics-extractor"),
		required_features: adapter.features(),
		required_limits: adapter.limits(),
		..Default::default()
	};

	pollster::block_on(adapter.request_device(&device_options)).unwrap()
}
