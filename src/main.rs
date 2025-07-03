use std::{
	fs,
	io::{BufRead, Write},
};

pub(crate) mod device;
pub(crate) mod solver;

#[cfg(test)]
pub(crate) mod tests;

#[derive(argh::FromArgs)]
/// Generates the remaining words in a BTC seed phrase by brute-force. Uses the WebGPU API
pub(crate) struct Config {
	/// string describing known and unknown words in the mnemonic sentence. Must be 12 words long
	#[argh(positional)]
	stencil: Vec<String>,
	/// solve for addresses in the range [start, end]. Maximum problem space is [0, 17592186044416] (2^44)
	#[argh(option, short = 'p', default = "(0,17592186044416)", from_str_fn(parse_partition))]
	range: (u64, u64),
	/// file containing list of known addresses to verify against
	#[argh(option, short = 'a')]
	addresses: Option<String>,
	/// file to which found addresses will be output
	#[argh(option, short = 'f')]
	found: Option<String>,
}

pub(crate) fn read_addresses_file(path: &str) -> gxhash::HashSet<solver::types::PublicKeyHash> {
	let file = std::fs::File::open(path).expect("Create an `addresses.txt`, containing P2PKH addresses to test against");
	let reader = std::io::BufReader::new(file);
	reader.lines().map(Result::unwrap).map(|l| parse_address(&l).unwrap()).collect()
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

	Ok(buf)
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

	// input and output file paths
	let output_path = config.found.as_deref().unwrap_or("found.txt");
	let addresses_path = config.addresses.as_deref().unwrap_or("addresses.txt");

	// start monitoring thread
	let (sender, receiver) = std::sync::mpsc::channel::<solver::SolverUpdate>();
	let addresses = read_addresses_file(addresses_path);
	let mut output_file = fs::File::open(output_path).expect("Create a `found.txt` file, for found addresses");

	let handle = std::thread::spawn(move || {
		println!("[000/000]: Result Collection Thread is starting...");
		let null_hash: solver::types::GpuSha512Hash = bytemuck::Zeroable::zeroed();

		// bitcoin state
		let secp256k1 = bitcoin::key::Secp256k1::new();
		let derivation_path: bitcoin::bip32::DerivationPath = std::str::FromStr::from_str("m/44'/0'/0'/0/0").unwrap();

		while let Ok(update) = receiver.recv() {
			let solver::SolverData::Hashes { hashes, .. } = update.data else {
				continue;
			};

			let iteration = (update.step / solver::THREADS_PER_DISPATCH as u64) + 1;
			println!("[{:03}/{:03}]: {} Addresses Found in {:?}", iteration, range, hashes.len(), then.elapsed());

			then = std::time::Instant::now();

			// process master extended keys
			for combined in IntoIterator::into_iter(hashes) {
				debug_assert_ne!(combined, null_hash);

				// TODO: Partially move derivations to GPU
				let combined = combined.map(|s| s as u8);

				let mut chain_code_bytes = [0; 32];
				chain_code_bytes.copy_from_slice(&combined[32..]);

				let master_extended_private_key = bitcoin::bip32::Xpriv {
					network: bitcoin::NetworkKind::Main,
					depth: 0,
					parent_fingerprint: bitcoin::bip32::Fingerprint::from([0; 4]),
					child_number: bitcoin::bip32::ChildNumber::Hardened { index: 0 },
					private_key: bitcoin::secp256k1::SecretKey::from_slice(&combined[..32]).unwrap(),
					chain_code: bitcoin::bip32::ChainCode::from(chain_code_bytes),
				};

				// derive child private key
				let child_private_key = master_extended_private_key.derive_priv(&secp256k1, &derivation_path).unwrap();

				// derive public key hash
				let public_key = bitcoin::PublicKey::from_private_key(&secp256k1, &child_private_key.to_priv());
				let public_key_hash = public_key.pubkey_hash();

				let bytes: &[u8; 20] = public_key_hash.as_ref();
				if addresses.contains(bytes) {
					// write to output file
					let p2pkh = bitcoin::Address::p2pkh(&public_key, bitcoin::Network::Bitcoin);
					let line = format!(
						"MasterExtendedKey = \"{}\", DerivedPrivateKey = \"{}\", P2PKH = \"{}\"\n",
						master_extended_private_key, child_private_key, p2pkh
					);

					println!("Found Matching P2PKH:\n{}", line);
					output_file.write_all(line.as_bytes()).unwrap();
				}
			}
		}
	});

	// solve
	solver::solve::<{ solver::HASHES_READ_FLAG }>(&config, &device, &queue, sender);
	handle.join().expect("Monitoring thread experienced an error");
}
