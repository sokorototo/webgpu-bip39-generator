const SHA512_BLOCK_SIZE = 128;
const SHA512_HASH_LENGTH = 64;
const SHA512_MAX_UPDATE_SIZE = 256;

// Constants for SHA-512 (moved outside of functions to avoid complex initialization)
const K: array<u64, 80> = array<u64, 80>(
    0x428a2f98d728ae22u, 0x7137449123ef65cdu, 0xb5c0fbcfec4d3b2fu, 0xe9b5dba58189dbbcu,
    0x3956c25bf348b538u, 0x59f111f1b605d019u, 0x923f82a4af194f9bu, 0xab1c5ed5da6d8118u,
    0xd807aa98a3030242u, 0x12835b0145706fbeu, 0x243185be4ee4b28cu, 0x550c7dc3d5ffb4e2u,
    0x72be5d74f27b896fu, 0x80deb1fe3b1696b1u, 0x9bdc06a725c71235u, 0xc19bf174c692694u,
    0xe49b69c19ef14ad2u, 0xefbe4786384f25e3u, 0x0fc19dc68b8cd5b5u, 0x240ca1cc77ac9c65u,
    0x2de92c6f592b0275u, 0x4a7484aa6ea6e483u, 0x5cb0a9dcbd41fbd4u, 0x76f988da831153b5u,
    0x983e5152ee66dfabu, 0xa831c66d2db43210u, 0xb00327c898fb213fu, 0xbf597fc7beef0ee4u,
    0xc6e00bf33da88fc2u, 0xd5a79147930aa725u, 0x06ca6351e003826fu, 0x142929670a0e6e70u,
    0x27b70a8546d22ffcu, 0x2e1b21385c26c926u, 0x4d2c6dfc5ac42aedu, 0x53380d139d95b3dfu,
    0x650a73548baf63deu, 0x766a0abb3c77b2a8u, 0x81c2c92e47edaee6u, 0x92722c851482353bu,
    0xa2bfe8a14cf10364u, 0xa81a664bbc423001u, 0xc24b8b70d0f89791u, 0xc76c51a30654be30u,
    0xd192e819d6ef5218u, 0xd69906245565a910u, 0xf40e35855771202au, 0x106aa07032bbd1b8u,
    0x19a4c116b8d2d0c8u, 0x1e376c085141ab53u, 0x2748774cdf8eeb99u, 0x34b0bcb5e19b48a8u,
    0x391c0cb3c5c95a63u, 0x4ed8aa4ae3418acbu, 0x5b9cca4f7763e373u, 0x682e6ff3d6b2b8a3u,
    0x748f82ee5defb2fcu, 0x78a5636f43172f60u, 0x84c87814a1f0ab72u, 0x8cc702081a6439ecu,
    0x90befffa23631e28u, 0xa4506cebde82bde9u, 0xbef9a3f7b2c67915u, 0xc67178f2e372532bu,
    0xca273eceea26619cu, 0xd186b8c721c0c207u, 0xeada7dd6cde0eb1eu, 0xf57d4f7fee6ed178u,
    0x06f067aa72176fbau, 0x0a637dc5a2c898a6u, 0x113f9804bef90daeu, 0x1b710b35131c471bu,
    0x28db77f523047d84u, 0x32caab7b40c72493u, 0x3c9ebe0a15c9bebcu, 0x431d67c49c100d4cu,
    0x4cc5d4becb3e42b6u, 0x597f299cfc657e2au, 0x5fcb6fab3ad6faecu, 0x6c44198c4a475817u
);

struct SHA512_CTX {
    state: array<u64, 8>,
    count: u64,
    buffer: array<u32, SHA512_BLOCK_SIZE>,
    fill: u32,
};

fn ROR(x: u64, n: u32) -> u64 {
    return (x >> n) | (x << (64u - n));
}

fn S0(x: u64) -> u64 { return ROR(x, 28u) ^ ROR(x, 34u) ^ ROR(x, 39u); }
fn S1(x: u64) -> u64 { return ROR(x, 14u) ^ ROR(x, 18u) ^ ROR(x, 41u); }
fn G0(x: u64) -> u64 { return ROR(x, 1u) ^ ROR(x, 8u) ^ (x >> 7u); }
fn G1(x: u64) -> u64 { return ROR(x, 19u) ^ ROR(x, 61u) ^ (x >> 6u); }

fn load_be64(data: ptr<function, array<u32, SHA512_BLOCK_SIZE>>, offset: u32) -> u64 {
    let base = offset * 8u;
    return (u64((*data)[base]) << 56u) | (u64((*data)[base + 1u]) << 48u) | (u64((*data)[base + 2u]) << 40u) | (u64((*data)[base + 3u]) << 32u) | (u64((*data)[base + 4u]) << 24u) | (u64((*data)[base + 5u]) << 16u) | (u64((*data)[base + 6u]) << 8u) | u64((*data)[base + 7u]);
}

fn store_be64(data: ptr<function, array<u32, SHA512_BLOCK_SIZE>>, x: u64, offset: u32) {
    let base = offset;
    (*data)[base] = u32((x >> 56u) & 0xffu);
    (*data)[base + 1u] = u32((x >> 48u) & 0xffu);
    (*data)[base + 2u] = u32((x >> 40u) & 0xffu);
    (*data)[base + 3u] = u32((x >> 32u) & 0xffu);
    (*data)[base + 4u] = u32((x >> 24u) & 0xffu);
    (*data)[base + 5u] = u32((x >> 16u) & 0xffu);
    (*data)[base + 6u] = u32((x >> 8u) & 0xffu);
    (*data)[base + 7u] = u32(x & 0xffu);
}

fn store_be64_out(data: ptr<function, array<u32, SHA512_HASH_LENGTH>>, x: u64, offset: u32) {
    let base = offset;
    (*data)[base] = u32((x >> 56u) & 0xffu);
    (*data)[base + 1u] = u32((x >> 48u) & 0xffu);
    (*data)[base + 2u] = u32((x >> 40u) & 0xffu);
    (*data)[base + 3u] = u32((x >> 32u) & 0xffu);
    (*data)[base + 4u] = u32((x >> 24u) & 0xffu);
    (*data)[base + 5u] = u32((x >> 16u) & 0xffu);
    (*data)[base + 6u] = u32((x >> 8u) & 0xffu);
    (*data)[base + 7u] = u32(x & 0xffu);
}

fn compress(state: ptr<function, array<u64, 8>>, buf: ptr<function, array<u32, SHA512_BLOCK_SIZE>>) {
    var W: array<u64, 80>;

    // Load the 16 64-bit words from the buffer
    for (var i = 0u; i < 16u; i++) {
        W[i] = load_be64(buf, i);
    }

    // Extend the 16 words to 80 words
    for (var i = 16u; i < 80u; i++) {
        W[i] = W[i - 16u] + G0(W[i - 15u]) + W[i - 7u] + G1(W[i - 2u]);
    }

    // Initialize working variables
    var a = (*state)[0];
    var b = (*state)[1];
    var c = (*state)[2];
    var d = (*state)[3];
    var e = (*state)[4];
    var f = (*state)[5];
    var g = (*state)[6];
    var h = (*state)[7];

    // Main loop
    for (var i = 0u; i < 80u; i++) {
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

    // Add the compressed chunk to the current hash value
    (*state)[0] += a;
    (*state)[1] += b;
    (*state)[2] += c;
    (*state)[3] += d;
    (*state)[4] += e;
    (*state)[5] += f;
    (*state)[6] += g;
    (*state)[7] += h;
}

fn sha512_init(ctx: ptr<function, SHA512_CTX>) {
    (*ctx).fill = 0u;
    (*ctx).count = 0u;

    // Initialize hash values (first 64 bits of the fractional parts of the square roots of the first 8 primes)
    (*ctx).state[0] = 0x6a09e667f3bcc908u;
    (*ctx).state[1] = 0xbb67ae8584caa73bu;
    (*ctx).state[2] = 0x3c6ef372fe94f82bu;
    (*ctx).state[3] = 0xa54ff53a5f1d36f1u;
    (*ctx).state[4] = 0x510e527fade682d1u;
    (*ctx).state[5] = 0x9b05688c2b3e6c1fu;
    (*ctx).state[6] = 0x1f83d9abfb41bd6bu;
    (*ctx).state[7] = 0x5be0cd19137e2179u;
}

fn sha512_update(ctx: ptr<function, SHA512_CTX>, data: ptr<function, array<u32, SHA512_MAX_UPDATE_SIZE>>, len: u32) {
    var remaining = len;
    var data_offset = 0u;

    // Handle any remaining data in buffer
    if (*ctx).fill > 0u {
        while (*ctx).fill < SHA512_BLOCK_SIZE && remaining > 0u {
            (*ctx).buffer[(*ctx).fill] = (*data)[data_offset];
            (*ctx).fill += 1u;
            data_offset += 1u;
            remaining -= 1u;
        }

        if (*ctx).fill < SHA512_BLOCK_SIZE {
            return;
        }

        compress(&(*ctx).state, &(*ctx).buffer);
        (*ctx).count += 1u;
        (*ctx).fill = 0u;
    }

    // Process complete blocks
    while remaining >= SHA512_BLOCK_SIZE {
        // Copy data to buffer
        for (var i = 0u; i < SHA512_BLOCK_SIZE; i++) {
            (*ctx).buffer[i] = (*data)[data_offset + i];
        }

        compress(&(*ctx).state, &(*ctx).buffer);
        (*ctx).count += 1u;
        data_offset += SHA512_BLOCK_SIZE;
        remaining -= SHA512_BLOCK_SIZE;
    }

    // Save remaining data
    for (var i = 0u; i < remaining; i++) {
        (*ctx).buffer[i] = (*data)[data_offset + i];
    }
    (*ctx).fill = remaining;
}

fn sha512_done(ctx: ptr<function, SHA512_CTX>) -> array<u32, SHA512_HASH_LENGTH> {
    var out: array<u32, SHA512_HASH_LENGTH>;
    let rest = u64((*ctx).fill);

    // Append the '1' bit (plus zero padding to make it a byte)
    (*ctx).buffer[(*ctx).fill] = 0x80u;
    (*ctx).fill += 1u;

    // If we don't have room for the length, process this block
    if (*ctx).fill > 112u {
        while (*ctx).fill < SHA512_BLOCK_SIZE {
            (*ctx).buffer[(*ctx).fill] = 0u;
            (*ctx).fill += 1u;
        }
        compress(&(*ctx).state, &(*ctx).buffer);
        (*ctx).fill = 0u;
    }

    // Pad with zeros
    while (*ctx).fill < 112u {
        (*ctx).buffer[(*ctx).fill] = 0u;
        (*ctx).fill += 1u;
    }

    // Append length in bits as 128-bit big-endian
    let bit_count = (((*ctx).count << 7u) | rest) << 3u;
    store_be64(&(*ctx).buffer, (*ctx).count >> 54u, 112u);
    store_be64(&(*ctx).buffer, bit_count, 120u);

    compress(&(*ctx).state, &(*ctx).buffer);

    // Produce the final hash value
    for (var i = 0u; i < 8u; i++) {
        store_be64_out(&out, (*ctx).state[i], 8u * i);
    }

    return out;
}