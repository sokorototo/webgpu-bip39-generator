use std::{collections::BTreeSet, io::BufRead};

pub(crate) mod bip39;
pub(crate) mod solver;

#[derive(Debug, argh::FromArgs)]
/// Generates the remaining words in a BTC seed phrase by brute-force. Uses the WebGPU API
pub(crate) struct Config {
	/// for running parallel instances on multiple machines, describes how to divide the entropy space for effective parallelization
	#[argh(option, short = 'p', default = "1")]
	partitions: usize,
	/// if the entropy space is divided, what partition do we assign ourselves
	#[argh(option, short = 'i', default = "0")]
	partition_idx: usize,
	/// file containing list of known addresses to verify against
	#[argh(option, short = 'a', default = "BTreeSet::new()", from_str_fn(read_file))]
	addresses: BTreeSet<String>,
	/// string describing known and unknown words in the mnemonic sentence. Must be 12 or 13 words long
	#[argh(positional, greedy)]
	stencil: Vec<String>,
}

pub(crate) fn read_file(path: &str) -> Result<BTreeSet<String>, String> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::with_capacity(64, file);
	Ok(reader.lines().map(|line| line.unwrap()).collect())
}

fn main() {
	let config: Config = argh::from_env();
	let wordlist = bip39::get_word_list();

	// verify
	if config.stencil.len() != 12 {
		panic!("Invalid Stencil: 12 words required, {} provided", config.stencil.len());
	}

	if let Some(unknown) = config.stencil.iter().find(|w| *w != "*" && !wordlist.contains(w.as_str())) {
		panic!("Invalid Stencil: Contains Unknown Word {}", unknown)
	};

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
	let adapter = pollster::block_on(instance.request_adapter(&adapter_options)).unwrap();

	// acquire device and queue
	let device_options = wgpu::DeviceDescriptor {
		label: Some("mnemonics-extractor"),
		required_features: adapter.features(),
		required_limits: adapter.limits(),
		..Default::default()
	};

	let (device, queue) = pollster::block_on(adapter.request_device(&device_options)).unwrap();

	// extract mnemonic seeds
	let then = std::time::Instant::now();
	let count = solver::extract_seeds(&config, &device, &queue);
	println!("Took: {:?}, Found Seeds: {:#?}. Written File: 'found.txt'", then.elapsed(), count);
}
