use super::*;

pub(super) fn verify_config(config: &Config) {
	// verify stencil words
	if config.range.1 > 2u64.pow(44) || config.range.0 > config.range.1 {
		panic!("Invalid Range: Maximum problem space is [0, 17592186044416] (2^44)");
	};

	if let Some(unknown) = config.stencil.iter().find(|w| *w != "_" && !bip39::Language::English.word_list().contains(&w.as_str())) {
		panic!("Invalid Stencil: Contains Unknown Word {}", unknown)
	};

	if config.stencil.len() != 12 || !config.stencil.iter().enumerate().all(|(idx, ss)| (4..8).contains(&idx) || (ss != "_")) {
		panic!("Invalid Stencil Pattern: Expected 4 words, 4 stars and 4 words\n Eg: throw roast bulk opinion * * * * guide female change thought");
	};

	log::info!("Verified Stencil and Config Range");
}
