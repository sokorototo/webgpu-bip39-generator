use std::io::BufRead;

pub(crate) mod device;
pub(crate) mod solver;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, Clone, argh::FromArgs)]
/// Generates the remaining words in a BTC seed phrase by brute-force. Uses the WebGPU API
pub(crate) struct Config {
	/// string describing known and unknown words in the mnemonic sentence. Must be 12 words long
	#[argh(positional)]
	stencil: Vec<String>,
	/// solve for addresses in the range [start, end]. Maximum problem space is [0, 17592186044416] (2^44)
	#[argh(option, short = 'p', default = "(0,17592186044416)", from_str_fn(parse_partition))]
	range: (u64, u64),
	/// file containing list of known addresses to verify against
	#[argh(option, short = 'a', default = "default_addresses_file()", from_str_fn(read_addresses_file))]
	addresses: gxhash::HashSet<solver::types::PublicKeyHash>,
}

pub(crate) fn default_addresses_file() -> gxhash::HashSet<solver::types::PublicKeyHash> {
	read_addresses_file("addresses.txt").unwrap()
}

pub(crate) fn read_addresses_file(path: &str) -> Result<gxhash::HashSet<solver::types::PublicKeyHash>, String> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::new(file);
	Ok(reader.lines().map(Result::unwrap).map(|l| parse_address(&l).unwrap()).collect())
}

pub(crate) fn parse_address(address: &str) -> Result<solver::types::PublicKeyHash, String> {
	use base58::FromBase58;

	let bytes = address.from_base58().unwrap();

	// P2PKH should be exactly 25 bytes
	if bytes.len() != 25 {
		return Err(format!("Invalid length: expected 25, got {}", bytes.len()));
	}

	// Verify version byte (0x00 for mainnet P2PKH)
	if bytes[0] != 0x00 {
		return Err("Not a P2PKH address".to_string());
	}

	// Extract the 20-byte hash160
	let mut buf = [0u8; 20];
	buf.copy_from_slice(&bytes[1..21]);

	Ok(buf.map(|b| b as u32))
}

pub(crate) fn parse_partition(path: &str) -> Result<(u64, u64), String> {
	let mut parts = path.split('/').take(2).map(|s| s.parse().unwrap());
	Ok((parts.next().unwrap(), parts.next().unwrap()))
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

	// stencil must match expected pattern of 4 words, 4 underscores and 4 words
	if config.stencil.len() != 12 || !config.stencil.iter().enumerate().all(|(idx, ss)| (4..8).contains(&idx) || (ss != "_")) {
		panic!("Invalid Stencil Pattern: Expected 4 words, 4 stars and 4 words\n Eg: throw roast bulk opinion * * * * guide female change thought");
	};

	// get device and device
	let (device, queue) = device::init().await;

	// progress tracking
	let mut then = std::time::Instant::now();
	let range = 1 + (config.range.1 - config.range.0) / solver::THREADS_PER_DISPATCH as u64;

	// start monitoring thread
	let (sender, receiver) = std::sync::mpsc::channel::<solver::SolverUpdate>();
	let handle = std::thread::spawn(move || {
		println!("Started Addresses Search Thread");

		while let Ok(update) = receiver.recv() {
			let solver::SolverData::Hashes { hashes, .. } = update.data else {
				continue;
			};

			let iteration = (update.step / solver::THREADS_PER_DISPATCH as u64) + 1;
			println!("[{:03}/{:03}]: {} Addresses Found in {:?}", iteration, range, hashes.len(), then.elapsed());

			then = std::time::Instant::now();
		}
	});

	// solve
	solver::solve::<{ solver::HASHES_READ_FLAG }>(&config, &device, &queue, sender);
	handle.join().expect("Monitoring thread experienced an error");
}
