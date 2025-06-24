const SHA512_BLOCK_SIZE	= 128;
const SHA512_HASH_LENGTH = 64;

const SHA512_MAX_INPUT_SIZE = 128;

struct SHA512_CTX {
    state: array<u64, 8>,
    count: u64,
    buffer: array<u32, SHA512_BLOCK_SIZE>,
    fill: u32,
};

// to be initialized later
const K = array<u64, 80>(
    0x428a2f98d728ae22lu, 0x7137449123ef65cdlu, 0xb5c0fbcfec4d3b2flu,
    0xe9b5dba58189dbbclu, 0x3956c25bf348b538lu, 0x59f111f1b605d019lu,
    0x923f82a4af194f9blu, 0xab1c5ed5da6d8118lu, 0xd807aa98a3030242lu,
    0x12835b0145706fbelu, 0x243185be4ee4b28clu, 0x550c7dc3d5ffb4e2lu,
    0x72be5d74f27b896flu, 0x80deb1fe3b1696b1lu, 0x9bdc06a725c71235lu,
    0xc19bf174cf692694lu, 0xe49b69c19ef14ad2lu, 0xefbe4786384f25e3lu,
    0x0fc19dc68b8cd5b5lu, 0x240ca1cc77ac9c65lu, 0x2de92c6f592b0275lu,
    0x4a7484aa6ea6e483lu, 0x5cb0a9dcbd41fbd4lu, 0x76f988da831153b5lu,
    0x983e5152ee66dfablu, 0xa831c66d2db43210lu, 0xb00327c898fb213flu,
    0xbf597fc7beef0ee4lu, 0xc6e00bf33da88fc2lu, 0xd5a79147930aa725lu,
    0x06ca6351e003826flu, 0x142929670a0e6e70lu, 0x27b70a8546d22ffclu,
    0x2e1b21385c26c926lu, 0x4d2c6dfc5ac42aedlu, 0x53380d139d95b3dflu,
    0x650a73548baf63delu, 0x766a0abb3c77b2a8lu, 0x81c2c92e47edaee6lu,
    0x92722c851482353blu, 0xa2bfe8a14cf10364lu, 0xa81a664bbc423001lu,
    0xc24b8b70d0f89791lu, 0xc76c51a30654be30lu, 0xd192e819d6ef5218lu,
    0xd69906245565a910lu, 0xf40e35855771202alu, 0x106aa07032bbd1b8lu,
    0x19a4c116b8d2d0c8lu, 0x1e376c085141ab53lu, 0x2748774cdf8eeb99lu,
    0x34b0bcb5e19b48a8lu, 0x391c0cb3c5c95a63lu, 0x4ed8aa4ae3418acblu,
    0x5b9cca4f7763e373lu, 0x682e6ff3d6b2b8a3lu, 0x748f82ee5defb2fclu,
    0x78a5636f43172f60lu, 0x84c87814a1f0ab72lu, 0x8cc702081a6439eclu,
    0x90befffa23631e28lu, 0xa4506cebde82bde9lu, 0xbef9a3f7b2c67915lu,
    0xc67178f2e372532blu, 0xca273eceea26619clu, 0xd186b8c721c0c207lu,
    0xeada7dd6cde0eb1elu, 0xf57d4f7fee6ed178lu, 0x06f067aa72176fbalu,
    0x0a637dc5a2c898a6lu, 0x113f9804bef90daelu, 0x1b710b35131c471blu,
    0x28db77f523047d84lu, 0x32caab7b40c72493lu, 0x3c9ebe0a15c9bebclu,
    0x431d67c49c100d4clu, 0x4cc5d4becb3e42b6lu, 0x597f299cfc657e2alu,
    0x5fcb6fab3ad6faeclu, 0x6c44198c4a475817lu
);

fn ROR(x: u64, n: u64) -> u64 { return u64(x >> u32(n)) | (x << (64 - u32(n))); }

fn S0(x: u64) -> u64 { return (ROR(x, 28) ^ ROR(x, 34) ^ ROR(x, 39)); }
fn S1(x: u64) -> u64 { return (ROR(x, 14) ^ ROR(x, 18) ^ ROR(x, 41)); }
fn G0(x: u64) -> u64 { return (ROR(x, 1) ^ ROR(x, 8) ^ (x >> 7)); }
fn G1(x: u64) -> u64 { return (ROR(x, 19) ^ ROR(x, 61) ^ (x >> 6)); }

// NOTE: modifies d and t
fn ROUND(i: u32, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, W: ptr<function, array<u64, 80>>) -> array<u64, 2> {
    var t: u64 = h + S1(e) + (g ^ (e & (f ^ g))) + K[i] + W[i];

    var d2: u64 = d + t;
    var h2: u64 = t + S0(a) + (((a | b) & c) | (a & b));

    return array<u64, 2>(d2, h2);
}

fn store_be64(ctx: ptr<function, SHA512_CTX>, x: u64, offset: u32) {
    (*ctx).buffer[0 + offset] = u32((x >> 56) & 0xff);
    (*ctx).buffer[1 + offset] = u32((x >> 48) & 0xff);
    (*ctx).buffer[2 + offset] = u32((x >> 40) & 0xff);
    (*ctx).buffer[3 + offset] = u32((x >> 32) & 0xff);
    (*ctx).buffer[4 + offset] = u32((x >> 24) & 0xff);
    (*ctx).buffer[5 + offset] = u32((x >> 16) & 0xff);
    (*ctx).buffer[6 + offset] = u32((x >> 8) & 0xff);
    (*ctx).buffer[7 + offset] = u32((x >> 0) & 0xff);
}

fn store_be64_out(p: ptr<function, array<u32, SHA512_HASH_LENGTH>>, x: u64, offset: u32) {
    p[0 + offset] = u32((x >> 56) & 0xff);
    p[1 + offset] = u32((x >> 48) & 0xff);
    p[2 + offset] = u32((x >> 40) & 0xff);
    p[3 + offset] = u32((x >> 32) & 0xff);
    p[4 + offset] = u32((x >> 24) & 0xff);
    p[5 + offset] = u32((x >> 16) & 0xff);
    p[6 + offset] = u32((x >> 8) & 0xff);
    p[7 + offset] = u32((x >> 0) & 0xff);
}

fn load_be64_ctx(ctx: ptr<function, SHA512_CTX>, offset: u32) -> u64 {
    return (u64((*ctx).buffer[0 + offset]) << 56) | (u64((*ctx).buffer[1 + offset]) << 48) | (u64((*ctx).buffer[2 + offset]) << 40) | (u64((*ctx).buffer[3 + offset]) << 32) | (u64((*ctx).buffer[4 + offset]) << 24) | (u64((*ctx).buffer[5 + offset]) << 16) | (u64((*ctx).buffer[6 + offset]) << 8) | (u64((*ctx).buffer[7 + offset]));
}

fn compress_ctx(ctx: ptr<function, SHA512_CTX>) {
    var W: array<u64, 80> = array<u64, 80>();
    var t: u64 = 0;

    var a: u64 = (*ctx).state[0];
    var b: u64 = (*ctx).state[1];
    var c: u64 = (*ctx).state[2];
    var d: u64 = (*ctx).state[3];
    var e: u64 = (*ctx).state[4];
    var f: u64 = (*ctx).state[5];
    var g: u64 = (*ctx).state[6];
    var h: u64 = (*ctx).state[7];

    for (var i = 0u; i < 16; i++) {
        W[i] = load_be64_ctx(ctx, 8u * i);
    };

    for (var i = 16; i < 80; i++) {
        W[i] = W[i-16] + G0(W[i-15]) + W[i-7] + G1(W[i-2]);
    };

    for (var i = 0u; i < 80; i++) {
        let T1 = h + S1(e) + ((e & f) ^ (~e & g)) + K[i] + W[i];
        let T2 = S0(a) + ((a & b) ^ (a & c) ^ (b & c));

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    (*ctx).state[0] += a;
    (*ctx).state[1] += b;
    (*ctx).state[2] += c;
    (*ctx).state[3] += d;
    (*ctx).state[4] += e;
    (*ctx).state[5] += f;
    (*ctx).state[6] += g;
    (*ctx).state[7] += h;
}


fn load_be64(buf: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, offset: u32) -> u64 {
    return (u64(buf[0 + offset]) << 56) | (u64(buf[1 + offset]) << 48) | (u64(buf[2 + offset]) << 40) | (u64(buf[3 + offset]) << 32) | (u64(buf[4 + offset]) << 24) | (u64(buf[5 + offset]) << 16) | (u64(buf[6 + offset]) << 8) | (u64(buf[7 + offset]));
}

fn sha512_compress(ctx: ptr<function, SHA512_CTX>, data: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, offset: u32) {
    var W: array<u64, 80> = array<u64, 80>();
    var t: u64 = 0;

    var a: u64 = (*ctx).state[0];
    var b: u64 = (*ctx).state[1];
    var c: u64 = (*ctx).state[2];
    var d: u64 = (*ctx).state[3];
    var e: u64 = (*ctx).state[4];
    var f: u64 = (*ctx).state[5];
    var g: u64 = (*ctx).state[6];
    var h: u64 = (*ctx).state[7];

    for (var i = 0u; i < 16; i++) {
        W[i] = load_be64(data, 8u * i);
    };

    for (var i = 16; i < 80; i++) {
        W[i] = W[i-16] + G0(W[i-15]) + W[i-7] + G1(W[i-2]);
    };

    for (var i = 0u; i < 80; i++) {
        let T1 = h + S1(e) + ((e & f) ^ (~e & g)) + K[i] + W[i];
        let T2 = S0(a) + ((a & b) ^ (a & c) ^ (b & c));

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    (*ctx).state[0] += a;
    (*ctx).state[1] += b;
    (*ctx).state[2] += c;
    (*ctx).state[3] += d;
    (*ctx).state[4] += e;
    (*ctx).state[5] += f;
    (*ctx).state[6] += g;
    (*ctx).state[7] += h;
}

fn sha512_init(ctx: ptr<function, SHA512_CTX>) {
    (*ctx).fill = 0;
    (*ctx).count = 0;

    (*ctx).state[0] = 0x6a09e667f3bcc908lu;
    (*ctx).state[1] = 0xbb67ae8584caa73blu;
    (*ctx).state[2] = 0x3c6ef372fe94f82blu;
    (*ctx).state[3] = 0xa54ff53a5f1d36f1lu;
    (*ctx).state[4] = 0x510e527fade682d1lu;
    (*ctx).state[5] = 0x9b05688c2b3e6c1flu;
    (*ctx).state[6] = 0x1f83d9abfb41bd6blu;
    (*ctx).state[7] = 0x5be0cd19137e2179lu;
}

fn sha512_update(ctx: ptr<function, SHA512_CTX>, data: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, _len: u32) {
    var len = _len;
    var data_offset = 0u;

    if (*ctx).fill > 0 {
		// fill internal buffer up and compact
        while (*ctx).fill < 128 && len > 0 {
            (*ctx).buffer[(*ctx).fill] = data[data_offset];

            (*ctx).fill += 1;
            data_offset += 1;
            len -= 1;
        }

        if (*ctx).fill < 128 { return; }

        compress_ctx(ctx);
        (*ctx).count += 1;
    }

	// ctx->fill is now zero
    while len >= 128 {
        sha512_compress(ctx, data, data_offset);
        (*ctx).count ++;

        data_offset += 128;
        len -= 128;
    }

	// save rest for next time
    for (var i = 0u; i < len; i++) {
        (*ctx).buffer[i] = data[i + data_offset];
    };

    (*ctx).fill = len;
}

fn sha512_done(ctx: ptr<function, SHA512_CTX>) -> array<u32, SHA512_HASH_LENGTH> {
    var out: array<u32, SHA512_HASH_LENGTH> = array<u32, SHA512_HASH_LENGTH>();
    var rest = u64((*ctx).fill);

	// append 1-bit to signal end of data
    (*ctx).buffer[(*ctx).fill] = 0x80;
    (*ctx).fill += 1;

    if (*ctx).fill > 112 {
        while (*ctx).fill < 128 { (*ctx).buffer[(*ctx).fill] = 0; (*ctx).fill += 1; };
        compress_ctx(ctx);
        (*ctx).fill = 0;
    }

    while (*ctx).fill < 112 { (*ctx).buffer[(*ctx).fill] = 0; (*ctx).fill++;}

	// because rest < 128 our message length is
	// L := 128*ctx->count + rest == (ctx->count<<7)|rest,
	// now convert L to number of bits and write out as 128bit big-endian.
    store_be64(ctx, (*ctx).count >> 54, 112);
    store_be64(ctx, (((*ctx).count << 7) | rest) << 3, 120);

    compress_ctx(ctx);

    for (var i = 0u; i < 8; i++) {
        store_be64_out(&out, (*ctx).state[i], 8 * i);
    }

    return out;
}

fn sha512(data: ptr<function, array<u32, SHA512_MAX_INPUT_SIZE>>, len: u32) -> array<u32, SHA512_HASH_LENGTH> {
    var ctx: SHA512_CTX;

    sha512_init(&ctx);
    sha512_update(&ctx, data, len);

    return sha512_done(&ctx);
}