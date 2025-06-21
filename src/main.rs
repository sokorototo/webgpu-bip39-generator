pub(crate) mod device;
pub(crate) mod solver;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, Clone, argh::FromArgs)]
/// Generates the remaining words in a BTC seed phrase by brute-force. Uses the WebGPU API
pub(crate) struct Config {
	/// string describing known and unknown words in the mnemonic sentence. Must be 12 or 13 words long
	#[argh(positional)]
	stencil: Vec<String>,
	/// solve for addresses in the range [start, end]. Maximum problem space is [0, 17592186044416] (2^44)
	#[argh(option, short = 'p', default = "(0,17592186044416)", from_str_fn(parse_partition))]
	range: (u64, u64),
	/// file containing list of known addresses to verify against
	#[argh(option, short = 'a', from_str_fn(parse_address))]
	address: solver::types::P2PKH_Address,
}

pub(crate) fn parse_address(path: &str) -> Result<[u32; 20], String> {
	use base58::FromBase58;

	let bytes = path.from_base58().unwrap();
	let mut buf = [0u8; 20];
	buf.copy_from_slice(&bytes[2..22]);

	Ok(buf.map(|b| b as u32))
}

pub(crate) fn parse_partition(path: &str) -> Result<(u64, u64), String> {
	let mut parts = path.split('/').take(2).map(|s| s.parse().unwrap());
	Ok((parts.next().unwrap(), parts.next().unwrap()))
}

pub(crate) fn handle_results(constants: &solver::types::PushConstants, addresses: &[solver::types::P2PKH_Address]) {
	// verifies output from solver
	let mut set = std::collections::BTreeSet::new();

	for address in addresses {
		assert!(set.insert(address[0]), "Duplicate Entropy Found: {}", address[0]);
		assert_eq!(constants.entropy, address[1], "Got Different Entropy from GPU");

		let input = [constants.words[0], address[2], address[3], constants.words[3]];
		let bytes: &[u8] = bytemuck::cast_slice(&input);

		let result = [address[4], address[5], address[6], address[7]].map(|s| s as u8);
		let expected = sha256_rs::sha256(bytes);

		assert_eq!(&result, &expected[..4], "Got Different Hash from Shader");
		assert!(result[0] & constants.checksum as u8 == result[0], "Got Different Checksum from Shader");
	}
}

#[pollster::main]
async fn main() {
	let config: Config = argh::from_env();

	// address range must be below 2^44
	if config.range.1 > 2u64.pow(44) || config.range.0 > config.range.1 {
		panic!("Invalid Range: Maximum problem space is [0, 17592186044416] (2^44)");
	};

	// stencil words must be valid
	if let Some(unknown) = config.stencil.iter().find(|w| *w != "_" && !bip39::Language::English.word_list().contains(&w.as_str())) {
		panic!("Invalid Stencil: Contains Unknown Word {}", unknown)
	};

	// stencil must match expected pattern of 4 words, 4 stars and 4 words
	if !config.stencil.iter().enumerate().all(|(idx, ss)| (4..8).contains(&idx) || (ss != "_")) {
		panic!("Invalid Stencil Pattern: Expected 4 words, 4 stars and 4 words\n Eg: throw roast bulk opinion * * * * guide female change thought");
	};

	// get device and device
	let (device, queue) = device::init().await;

	// extract mnemonic seeds
	let then = std::time::Instant::now();
	solver::solve(&config, &device, &queue, handle_results);

	println!("Took: {:?}, Written File: 'found.txt'", then.elapsed());
}
