pub(crate) mod bip39;

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
	#[argh(option, short = 'a', default = "String::from(\"addresses.txt\")")]
	addresses: String,
	/// string describing known and unknown words in the mnemonic sentence. Must be 12 or 13 words long
	#[argh(positional, greedy)]
	stencil: Vec<String>,
}

fn main() {
	let Config {
		partitions,
		partition_idx,
		addresses,
		mut stencil,
	} = argh::from_env();
	let wordlist = bip39::get_word_list();

	// verify
	if stencil.len() != 12 && stencil.len() != 13 {
		panic!("Invalid Stencil: 12 or 13 words required, {} provided", stencil.len());
	}

	if let Some(unknown) = stencil.iter().find(|w| *w != "*" && !wordlist.contains(w.as_str())) {
		panic!("Invalid Stencil: Contains Unknown Word {}", unknown)
	};

	// Get passphrase
	let passphrase = (stencil.len() == 13).then(|| stencil.pop()).flatten();
	println!("Passphrase: {:?}, Stencil: {:?}", passphrase, stencil)
}
