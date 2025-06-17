use std::{collections::BTreeSet, io::BufRead};

pub(crate) mod bip39;
pub(crate) mod device;
pub(crate) mod solver;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, argh::FromArgs)]
/// Generates the remaining words in a BTC seed phrase by brute-force. Uses the WebGPU API
pub(crate) struct Config {
	/// for running parallel instances on multiple machines, describes how to divide the entropy space for effective parallelization
	#[argh(option, short = 'p', default = "(1,1)", from_str_fn(parse_partition))]
	partition: (usize, usize),
	/// file containing list of known addresses to verify against
	#[argh(option, short = 'a', default = "BTreeSet::new()", from_str_fn(read_file))]
	addresses: BTreeSet<String>,
	/// string describing known and unknown words in the mnemonic sentence. Must be 12 or 13 words long
	#[argh(positional, greedy)]
	stencil: Vec<String>,
}

pub(crate) fn parse_partition(path: &str) -> Result<(usize, usize), String> {
	let mut parts = path.split('/').take(2).map(|s| s.parse().unwrap());
	Ok((parts.next().unwrap(), parts.next().unwrap()))
}

pub(crate) fn read_file(path: &str) -> Result<BTreeSet<String>, String> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::with_capacity(64, file);
	Ok(reader.lines().map(|line| line.unwrap()).collect())
}

#[pollster::main]
async fn main() {
	let config: Config = argh::from_env();
	let wordlist = bip39::get_word_list();

	// verify
	if config.stencil.len() != 12 {
		panic!("Invalid Stencil: 12 words required, {} provided", config.stencil.len());
	}

	if let Some(unknown) = config.stencil.iter().find(|w| *w != "*" && !wordlist.contains(w.as_str())) {
		panic!("Invalid Stencil: Contains Unknown Word {}", unknown)
	};

	assert!(config.stencil.last().map(|s| s == "umbrella").unwrap_or(false), "Last Word Must Be Umbrella");

	// get device and device
	let (device, queue) = device::init().await;

	// extract mnemonic seeds
	let then = std::time::Instant::now();
	let count = solver::extract_seeds(&config, &device, &queue);
	println!("Took: {:?}, Found Seeds: {:#?}. Written File: 'found.txt'", then.elapsed(), count);
}
