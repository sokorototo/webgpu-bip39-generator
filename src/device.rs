pub(crate) async fn init() -> (wgpu::Device, wgpu::Queue) {
	// user modern DXC
	#[cfg(target_os = "windows")]
	let backend_options = wgpu::BackendOptions {
		dx12: wgpu::Dx12BackendOptions {
			shader_compiler: wgpu::Dx12Compiler::DynamicDxc {
				dxc_path: concat!(env!("CARGO_MANIFEST_DIR"), "/dxc/x64/dxcompiler.dll").to_string(),
				dxil_path: concat!(env!("CARGO_MANIFEST_DIR"), "/dxc/x64/dxil.dll").to_string(),
				max_shader_model: wgpu::DxcShaderModel::V6_7,
			},
		},
		..Default::default()
	};

	#[cfg(not(target_os = "windows"))]
	let backend_options = Default::default();

	// acquire instance
	let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
		backends: wgpu::Instance::enabled_backend_features(),
		backend_options,
		flags: if cfg!(debug_assertions) {
			wgpu::InstanceFlags::advanced_debugging()
		} else {
			wgpu::InstanceFlags::default()
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
		eprintln!("Uncaptured error: {}", err);
	}));

	device.set_device_lost_callback(Box::new(|err, cb| {
		panic!("Device lost: {:?}. Message: {}", err, cb);
	}));

	(device, queue)
}
