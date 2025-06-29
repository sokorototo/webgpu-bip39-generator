const BLOCK_SIZE = 128;
const IPAD = 0x36u;
const OPAD = 0x5cu;

fn hmac_sha512_init(ctx: ptr<function, SHA512_CTX>, key: ptr<function, array<u32, BLOCK_SIZE>>) {
    var pad = array<u32, SHA512_MAX_INPUT_SIZE>();

    // apply inner padding
    for (var i = 0; i < BLOCK_SIZE; i++) {
        pad[i] = key[i] ^ IPAD;
    }

	// init sha512
    sha512_init(ctx);
    sha512_update(ctx, &pad, BLOCK_SIZE);
}

fn hmac_sha512_done(ctx: ptr<function, SHA512_CTX>, key: ptr<function, array<u32, BLOCK_SIZE>>, out: ptr<function, array<u32, 128>>) {
    var pad = array<u32, SHA512_MAX_INPUT_SIZE>();

   //  construct outer padding
    for (var i = 0; i < BLOCK_SIZE; i++) {
        pad[i] = key[i] ^ OPAD;
    }

    // finalize inner hash
    var ihash = array<u32, 128>();
    sha512_done(ctx, &ihash);

    sha512_init(ctx);
    sha512_update(ctx, &pad, BLOCK_SIZE);

    // oversized inner buffer to avoid copying
    sha512_update(ctx, &ihash, SHA512_HASH_LENGTH);
    sha512_done(ctx, out);
}

// We know salt is "mnemonic" LOL
fn pbkdf2(
    passwd: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, passlen: u32,
    salt: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, saltlen: u32,
    iter: u32, out: ptr<function, array<u32, SHA512_HASH_LENGTH>>) {
    // cache hmac-state
    var cached: SHA512_CTX;
    hmac_sha512_init(&cached, passwd);

    // bleh bleh bleh
    var hmac: SHA512_CTX = cached;
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
    var U = array<u32, SHA512_MAX_INPUT_SIZE>();
    hmac_sha512_done(&hmac, passwd, &U);
    var F = U;

    for (var j = 1u; j < iter; j++) {
        // reset hmac state to cached
        hmac = cached;

        // update hmac with previous hash
        sha512_update(&hmac, &U, SHA512_HASH_LENGTH);
        hmac_sha512_done(&hmac, passwd, &U);

        for (var k = 0u; k < SHA512_HASH_LENGTH; k += 8) {
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

    // write final hash to output
    for (var i = 0u; i < SHA512_HASH_LENGTH; i++) {
        out[i] = F[i];
    };
}
