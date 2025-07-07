use std::{
	fs,
	io::{BufRead, Write},
};

pub(crate) mod device;
pub(crate) mod solver;
pub(self) mod utils;

#[cfg(test)]
pub(crate) mod tests;

#[derive(argh::FromArgs, Clone, Default)]
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
	/// how many threads to process per iteration in the derivation stage.
	/// multiplied by 256 to arrive at final value. Default is 64
	#[argh(option, short = 'd')]
	dispatch: Option<u32>,
}

pub(crate) fn read_addresses_file(path: &str) -> gxhash::HashSet<solver::types::PublicKeyHash> {
	let Ok(file) = fs::File::open(path) else {
		log::error!("Create an `{}`, containing P2PKH addresses to test against", path);
		std::process::exit(1);
	};

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
	if cfg!(debug_assertions) {
		simple_logger::SimpleLogger::new()
			.with_module_level("wgpu_hal", log::LevelFilter::Warn)
			.with_module_level("wgpu_core", log::LevelFilter::Warn)
			.with_module_level("naga", log::LevelFilter::Error)
			.with_level(log::LevelFilter::Debug)
			.init()
			.unwrap();
	} else {
		simple_logger::init_with_level(log::Level::Info).unwrap();
	}

	// acquire and verify config
	let config: Config = argh::from_env();
	utils::verify_config(&config);

	// initialize device and device
	let (device, queue) = device::init().await;

	// start monitoring thread
	let config_ = config.clone();
	let mut then = std::time::Instant::now();
	let (sender, receiver) = flume::unbounded::<solver::StageComputation>();

	let handle = std::thread::spawn(move || {
		log::debug!("Result collection thread has started");

		// track progress
		let steps = 1 + (config.range.1 - config.range.0) / solver::STEP as u64;

		// input and output files
		let output_path = config.found.as_deref().unwrap_or("found.txt");
		let Ok(mut output_file) = fs::OpenOptions::new().write(true).create(true).open(output_path) else {
			log::error!("Create a `{}` file to output found addresses to", output_path);
			std::process::exit(1);
		};

		let addresses_path = config.addresses.as_deref().unwrap_or("addresses.txt");
		let addresses = read_addresses_file(addresses_path);

		log::info!("Output Addresses = \"{}\", Input Addresses = \"{}\"", output_path, addresses_path);
		log::debug!("Parsed Addresses Set: Len = {}", addresses.len());

		// bitcoin state
		let secp256k1 = bitcoin::key::Secp256k1::new();
		let derivation_path: bitcoin::bip32::DerivationPath = std::str::FromStr::from_str("m/44'/0'/0'/0/0").unwrap();
		let null_hash: [u32; 64] = bytemuck::Zeroable::zeroed();

		// performance tracking
		let mut found = 0u32;

		// consume messages
		loop {
			let count = receiver.len();
			if count >= 64 {
				log::error!(target: "main::monitoring_thread", "Severe Bottleneck from monitoring thread: Queue length = {}", receiver.len())
			}

			if count == 0 {
				continue;
			} else {
				log::debug!(target: "main::monitoring_thread", "Processing {} master extended keys", count);
			}

			let mut max_step = 0;
			let mut total = 0;

			for solver::StageComputation { step, constants, outputs } in receiver.drain() {
				max_step = max_step.max(step);
				total += outputs.len();

				// process master extended keys
				for (idx, output) in IntoIterator::into_iter(outputs).enumerate() {
					if output.hash == null_hash {
						log::error!("Step = {}, Thread = {}, Word2 = {}, returned a null result", step, idx, output.word2);
						continue;
					}

					// TODO: Partially move derivations to GPU
					let combined = output.hash.map(|s| s as u8);

					let mut chain_code_bytes = [0; 32];
					chain_code_bytes.copy_from_slice(&combined[32..]);

					// TODO: use custom code for key derivation
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
						found += 1;

						// assemble mnemonic sequence
						let entropy = [constants.word0, constants.word1, output.word2, constants.word3];
						let entropy_be = entropy.map(|e| e.to_be());
						let mnemonic = bip39::Mnemonic::from_entropy(bytemuck::cast_slice(&entropy_be)).unwrap();

						let first = mnemonic.words().next().unwrap();
						let sequence = mnemonic.words().skip(1).fold(first.to_string(), |acc, nxt| acc + " " + nxt);

						// write to output file
						let p2pkh = bitcoin::Address::p2pkh(&public_key, bitcoin::Network::Bitcoin);
						let line = format!("Mnemonic = \"{}\", MasterExtendedKey = \"{}\",  P2PKH = \"{}\"\n", sequence, master_extended_private_key, p2pkh);

						log::warn!("Found Match: {}", line);
						output_file.write_all(line.as_bytes()).unwrap();
					}
				}
			}

			// log performance
			let progress = (max_step / solver::STEP as u64) + 1;
			log::info!(target: "main::monitoring_thread", "[{:03}/{:03}]: {} Addresses processed in {:?}", progress, steps, total, then.elapsed());
			then = std::time::Instant::now();

			// break if we are done
			if progress == steps {
				break found;
			}
		}
	});

	// solve
	solver::solve(&config_, &device, &queue, sender);
	let found = handle.join().expect("Monitoring thread experienced an error");
	log::warn!("Completed Scan, Found: {} Matches", found);
}
