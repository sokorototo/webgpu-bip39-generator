pub(crate) async fn init() -> (wgpu::Device, wgpu::Queue) {
	#[cfg(not(debug_assertions))]
	let flags = wgpu::InstanceFlags::default();

	#[cfg(debug_assertions)]
	let flags = wgpu::InstanceFlags::advanced_debugging();

	// configure wgpu
	let instance_desc = wgpu::InstanceDescriptor {
		backends: wgpu::Instance::enabled_backend_features(),
		flags,
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
		required_features: adapter.features() | wgpu::Features::PUSH_CONSTANTS | wgpu::Features::SHADER_INT64,
		required_limits: adapter.limits(),
		..Default::default()
	};

	let (device, queue) = pollster::block_on(adapter.request_device(&device_options)).unwrap();

	// init error handling
	device.on_uncaptured_error(Box::new(|err| {
		eprintln!("Uncaptured error: {}", err);
	}));

	(device, queue)
}
