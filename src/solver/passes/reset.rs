use super::*;

pub(crate) struct ResetPass {
	pub pipeline: wgpu::ComputePipeline,
	pub bind_group: wgpu::BindGroup,
}
	
impl ResetPass {
	pub(crate) const DISPATCH_SIZE_X: u32 = 1;
	pub(crate) const DISPATCH_SIZE_Y: u32 = 1;

	/// Pass that resets the count buffer to zero.
	pub(crate) fn new(device: &wgpu::Device, filter_pass: &filter::FilterPass) -> ResetPass {
		// compile shader
		let source = include_str!("reset_stage.wgsl");
		let descriptor = wgpu::ShaderModuleDescriptor {
			label: Some("reset_main"),
			source: wgpu::ShaderSource::Wgsl(source.into()),
		};

		#[cfg(debug_assertions)]
		let shader = device.create_shader_module(descriptor);
		#[cfg(not(debug_assertions))]
		let shader = unsafe { device.create_shader_module_trusted(descriptor, wgpu::ShaderRuntimeChecks::unchecked()) };

		// configure bind group layout
		let descriptor = wgpu::BindGroupLayoutDescriptor {
			label: Some("reset_bind_group_layout"),
			entries: &[wgpu::BindGroupLayoutEntry {
				binding: 1,
				visibility: wgpu::ShaderStages::COMPUTE,
				ty: wgpu::BindingType::Buffer {
					ty: wgpu::BufferBindingType::Storage { read_only: false },
					has_dynamic_offset: false,
					min_binding_size: None,
				},
				count: None,
			}],
		};

		let bind_group_layout = device.create_bind_group_layout(&descriptor);

		// configure bind groups
		let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
			label: Some("reset_bind_group"),
			layout: &bind_group_layout,
			entries: &[wgpu::BindGroupEntry {
				binding: 1,
				resource: filter_pass.count_buffer.as_entire_binding(),
			}],
		});

		// configure pipeline layout
		let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
			label: Some("reset_pipeline_layout"),
			bind_group_layouts: &[&bind_group_layout],
			push_constant_ranges: &[],
		});

		// create compute pipeline
		let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
			label: Some("reset_pipeline"),
			module: &shader,
			entry_point: Some("main"),
			layout: Some(&pipeline_layout),
			// defaults
			cache: None,
			compilation_options: Default::default(),
		});

		ResetPass { pipeline, bind_group }
	}
}
