const HLEN = 64;
const IPAD = 0x36u;
const OPAD = 0x5cu;
const BS = 128;

// TODO: Maybe pass key by reference?
fn hmac_sha512_init(ctx: ptr<function, SHA512_CTX>, key: ptr<function, array<u32, BS>>) {
    var pad = array<u32, SHA512_MAX_INPUT_SIZE>();

    // apply inner padding
    for (var i = 0; i < BS; i++) {
        pad[i] = key[i] ^ IPAD;
    }

	 // init sha512
    sha512_init(ctx);
    sha512_update(ctx, &pad, BS);
}

fn hmac_sha512_done(ctx: ptr<function, SHA512_CTX>, key: ptr<function, array<u32, BS>>, result: ptr<function, array<u32, HLEN>>) {
    var pad = array<u32, SHA512_MAX_INPUT_SIZE>();

   //  construct outer padding
    for (var i = 0; i < BS; i++) {
        pad[i] = key[i] ^ OPAD;
    }

    // finalize inner hash
    var ihash: array<u32, HLEN> = sha512_done(ctx);

    sha512_init(ctx);
    sha512_update(ctx, &pad, BS);

	 // re-use pad buffer to hash pad
    for (var i = 0; i < HLEN; i++) {
        pad[i] = ihash[i];
    }
    sha512_update(ctx, &pad, HLEN);

    *result = sha512_done(ctx);
}

// We know salt is "mnemonic" LOL
fn pbkdf2(passwd: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, passlen: u32, salt: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, saltlen: u32, iter: u32) -> array<u32, HLEN> {
	var hmac: SHA512_CTX;
	// passlen <= 128 always, and passwd is zero delimited
	let key = passwd;

    hmac_sha512_init(&hmac, key);
    sha512_update(&hmac, salt, saltlen);

	 // for preparing data to be hashed by sha512
    var scratch = array<u32, SHA512_MAX_INPUT_SIZE>();

     // copy be32i into scratch and update hmac_state
    var be32i_bytes = array<u32, 4>(0u, 0u, 0u, 1u);
    for (var i = 0; i < 4; i++) {
        scratch[i] = be32i_bytes[i];
    }

	 // start digest
    var F = array<u32, HLEN>();
    var U = array<u32, HLEN>();

    sha512_update(&hmac, &scratch, 4);
    hmac_sha512_done(&hmac, key, &U);

    F = U;

    for (var j = 1u; j < iter; j++) {
        hmac_sha512_init(&hmac, key);

        for (var i = 0u; i < HLEN; i++) {
            scratch[i] = U[i];
        }

        sha512_update(&hmac, &scratch, HLEN);
        hmac_sha512_done(&hmac, key, &U);

        for (var k = 0u; k < HLEN; k++) {
            F[k] ^= U[k];
        }
    }

    return F;
}
