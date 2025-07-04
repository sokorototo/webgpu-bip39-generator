pub(crate) async fn init() -> (wgpu::Device, wgpu::Queue) {
	// acquire instance
	let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
		backends: wgpu::Instance::enabled_backend_features(),
		flags: if cfg!(any(debug_assertions, target_os = "linux")) {
			wgpu::InstanceFlags::GPU_BASED_VALIDATION | wgpu::InstanceFlags::DEBUG
		} else {
			wgpu::InstanceFlags::empty()
		},
		..Default::default()
	});

	// acquire adapter
	let adapter = instance
		.request_adapter(&wgpu::RequestAdapterOptions {
			power_preference: wgpu::PowerPreference::HighPerformance,
			..Default::default()
		})
		.await
		.unwrap();

	// acquire device and queue
	let device_options = wgpu::DeviceDescriptor {
		label: Some("address_extractor"),
		required_features: adapter.features() | wgpu::Features::PUSH_CONSTANTS | wgpu::Features::SHADER_INT64,
		required_limits: adapter.limits(),
		..Default::default()
	};

	let (device, queue) = pollster::block_on(adapter.request_device(&device_options)).unwrap();

	// init error handling
	device.on_uncaptured_error(Box::new(|err| {
		log::error!("Uncaptured error: {}", err);
	}));

	device.set_device_lost_callback(Box::new(|err, cb| {
		panic!("Device lost: {:?}. Message: {}", err, cb);
	}));

	log::info!("Initialized Device");

	(device, queue)
}
