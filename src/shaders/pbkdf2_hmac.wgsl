const PBKDF2_HMAC_SALT_LEN = 32;

const HLEN = 64;
const IPAD = 0x36u;
const OPAD = 0x5cu;
const BS = 64;

fn htobe32(x: u32) -> u32 {
    let b0 = (x >> 24) & 0x000000FFu;
    let b1 = (x >> 8) & 0x0000FF00u;
    let b2 = (x << 8) & 0x00FF0000u;
    let b3 = (x << 24) & 0xFF000000u;
    return b0 | b1 | b2 | b3;
}

// TODO: Maybe pass key by reference?
fn hmac_sha512_init(ctx: ptr<function, SHA512_CTX>, key: array<u32, BS>) {
    var pad = array<u32, SHA512_MAX_INPUT_SIZE>();

    // apply inner padding
    for (var i = 0; i < BS; i++) {
        pad[i] = key[i] ^ IPAD;
    }

	 // init sha512
    sha512_init(ctx);
    sha512_update(ctx, &pad, BS);
}

fn hmac_sha512_done(ctx: ptr<function, SHA512_CTX>, key: array<u32, BS>, result: ptr<function, array<u32, HLEN>>) {
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
fn pbkdf2_hmac_sha512(passwd: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, passlen: u32, salt: ptr<function, array<u32, PBKDF2_HMAC_SALT_LEN>>, saltlen: u32, iter: u32) -> array<u32, HLEN> {
    var hmac: SHA512_CTX;
    var key = array<u32, BS>();

	 // vartime code to handle password hmac - style
    if passlen < BS {
        for (var i = 0u; i < passlen; i++) {
            key[i] = passwd[i];
        }
    } else {
        sha512_init(&hmac);
        sha512_update(&hmac, passwd, passlen);
        key = sha512_done(&hmac);
    }

	 // for preparing data to be hashed by sha512
    var scratch = array<u32, SHA512_MAX_INPUT_SIZE>();

    for (var i = 0u; i <= saltlen; i++) {
        scratch[i] = salt[i];
    }

    hmac_sha512_init(&hmac, key);
    sha512_update(&hmac, &scratch, saltlen);

     // copy be32i into scratch and update hmac_state
    var be32i_bytes = array<u32, 4>(0u, 0u, 0u, 1u);
    for (var i = 0; i <= 4; i++) {
        scratch[i] = be32i_bytes[i];
    }

	 // start digest
    var F = array<u32, HLEN>();
    var U = array<u32, HLEN>();

    sha512_update(&hmac, &scratch, 4);
    hmac_sha512_done(&hmac, key, &U);

    F = U;

    for (var j = 2u; j <= iter; j++) {
        hmac_sha512_init(&hmac, key);

        for (var i = 0u; i <= HLEN; i++) {
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
