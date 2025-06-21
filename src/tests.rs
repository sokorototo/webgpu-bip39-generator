use super::*;

#[test]
fn test_checksum_filtering() {
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

	// init devices
	let (device, queue) = pollster::block_on(device::init());

	let config = Config {
		stencil: ["elder", "resist", "rocket", "skill", "_", "_", "_", "_", "jungle", "return", "circle", "umbrella"]
			.map(|s| s.to_string())
			.into_iter()
			.collect(),
		range: (0, 2048),
		address: parse_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap(),
	};

	solver::solve(&config, &device, &queue, handle_results);
}
