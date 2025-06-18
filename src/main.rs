use std::{collections::BTreeSet, io::BufRead};

pub(crate) mod device;
pub(crate) mod solver;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, argh::FromArgs)]
/// Generates the remaining words in a BTC seed phrase by brute-force. Uses the WebGPU API
pub(crate) struct Config {
	/// string describing known and unknown words in the mnemonic sentence. Must be 12 or 13 words long
	#[argh(positional)]
	stencil: Vec<String>,
	/// solve for addresses in the range [start, end]. Maximum problem space is [0, 17592186044416] (2^44)
	#[argh(option, short = 'p', default = "(0,17592186044416)", from_str_fn(parse_partition))]
	range: (u64, u64),
	/// file containing list of known addresses to verify against
	#[argh(option, short = 'a', default = "BTreeSet::new()", from_str_fn(read_file))]
	addresses: BTreeSet<String>,
}

pub(crate) fn parse_partition(path: &str) -> Result<(u64, u64), String> {
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

	// ensure all stencil words are valid
	if let Some(unknown) = config.stencil.iter().find(|w| *w != "*" && !bip39::Language::English.word_list().contains(&w.as_str())) {
		panic!("Invalid Stencil: Contains Unknown Word {}", unknown)
	};

	// ensure stencil matches expected pattern of 4 words, 4 stars and 4 words
	if !config.stencil.iter().enumerate().all(|(idx, ss)| (4..8).contains(&idx) || (ss != "*")) {
		panic!("Invalid Stencil Pattern: Expected 4 words, 4 stars and 4 words\n Eg: throw roast bulk opinion * * * * guide female change thought");
	};

	// get device and device
	let (device, queue) = device::init().await;

	// extract mnemonic seeds
	let then = std::time::Instant::now();
	solver::solve(&config, &device, &queue);

	println!("Took: {:?}, Written File: 'found.txt'", then.elapsed());
}
