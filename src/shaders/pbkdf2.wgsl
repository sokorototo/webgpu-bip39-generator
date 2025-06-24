const HLEN = 64;
const IPAD = 0x36u;
const OPAD = 0x5cu;
const BS = 128;

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

fn hmac_sha512_done(ctx: ptr<function, SHA512_CTX>, key: ptr<function, array<u32, BS>>) -> array<u32, HLEN> {
    var pad = array<u32, SHA512_MAX_INPUT_SIZE>();

   //  construct outer padding
    for (var i = 0; i < BS; i++) {
        pad[i] = key[i] ^ OPAD;
    }

    // finalize inner hash
    var ihash = sha512_done(ctx);

    sha512_init(ctx);
    sha512_update(ctx, &pad, BS);

	 // re-use pad buffer to hash pad
    for (var i = 0; i < HLEN; i++) {
        pad[i] = ihash[i];
    }
    sha512_update(ctx, &pad, HLEN);

    return sha512_done(ctx);
}

// We know salt is "mnemonic" LOL
fn pbkdf2(passwd: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, passlen: u32, salt: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, saltlen: u32, iter: u32) -> array<u32, HLEN> {
    // cache hmac-state
    var cached: SHA512_CTX;
    hmac_sha512_init(&cached, passwd);

    // bleh bleh bleh
    var hmac: SHA512_CTX;
    let key = passwd;

    hmac = cached;
    sha512_update(&hmac, salt, saltlen);

	// for preparing data to be hashed by sha512
    var scratch = array<u32, SHA512_MAX_INPUT_SIZE>();

    // copy be32i into scratch and update hmac_state
    var be32i_bytes = array<u32, 4>(0u, 0u, 0u, 1u);
    for (var i = 0; i < 4; i++) {
        scratch[i] = be32i_bytes[i];
    }

    sha512_update(&hmac, &scratch, 4);

    // start digest
    var U = hmac_sha512_done(&hmac, key);
    var F = U;

    for (var j = 1u; j < iter; j++) {
        hmac = cached;

        for (var i = 0u; i < HLEN; i++) {
            scratch[i] = U[i];
        }

        sha512_update(&hmac, &scratch, HLEN);
        U = hmac_sha512_done(&hmac, key);

        for (var k = 0u; k < HLEN; k += 8) {
            F[k] ^= U[k];
            F[k + 1] ^= U[k + 1];
            F[k + 2] ^= U[k + 2];
            F[k + 3] ^= U[k + 3];
            F[k + 4] ^= U[k + 4];
            F[k + 5] ^= U[k + 5];
            F[k + 6] ^= U[k + 6];
            F[k + 7] ^= U[k + 7];
        }
    }

    return F;
}
