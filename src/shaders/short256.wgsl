struct SHA256_CTX {
    data: array<u32, 64>,
    datalen: u32,
    bitlen: array<u32, 2>,
    state: array<u32, 8>,
    info: u32,
};

const SHA256_BLOCK_SIZE = 32;
// we consume 4 words: 32 bit integers
const KIBBLE_COUNT = 4;
// we hash 16 bytes at one go
const BYTES_COUNT = 16;

const k = array<u32, 64>(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

fn ROTRIGHT(a: u32, b: u32) -> u32 { return (((a) >> (b)) | ((a) << (32 - (b)))); }

fn CH(x: u32, y: u32, z: u32) -> u32 { return (((x) & (y)) ^ (~(x) & (z))); }
fn MAJ(x: u32, y: u32, z: u32) -> u32 { return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))); }
fn EP0(x: u32) -> u32 { return (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22)); }
fn EP1(x: u32) -> u32 { return (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25)); }
fn SIG0(x: u32) -> u32 { return (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3)); }
fn SIG1(x: u32) -> u32 { return (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10)); }

// Maps a dense u32 -> [u8; 4] -> [u32; 4]
fn extract_bytes_be(input: u32) -> array<u32, 4> {
    var bytes: array<u32, 4>;

    bytes[3] = (input >> 0u) & 0xFFu;
    bytes[2] = (input >> 8u) & 0xFFu;
    bytes[1] = (input >> 16u) & 0xFFu;
    bytes[0] = (input >> 24u) & 0xFFu;

    return bytes;
}

fn short256_transform(ctx: ptr<function, SHA256_CTX>) {
    var a: u32;
    var b: u32;
    var c: u32;
    var d: u32;
    var e: u32;
    var f: u32;
    var g: u32;
    var h: u32;
    var i: u32 = 0;
    var j: u32 = 0;
    var t1: u32;
    var t2: u32;
    var m: array<u32, 64> ;


    while i < 16 {
        m[i] = ((*ctx).data[j] << 24) | ((*ctx).data[j + 1] << 16) | ((*ctx).data[j + 2] << 8) | ((*ctx).data[j + 3]);
        i++;
        j += 4;
    }

    while i < 64 {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
        i++;
    }

    a = (*ctx).state[0];
    b = (*ctx).state[1];
    c = (*ctx).state[2];
    d = (*ctx).state[3];
    e = (*ctx).state[4];
    f = (*ctx).state[5];
    g = (*ctx).state[6];
    h = (*ctx).state[7];

    i = 0;
    for (; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
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

fn short256_update(ctx: ptr<function, SHA256_CTX>, input: array<u32, BYTES_COUNT>) {
    for (var i: u32 = 0; i < BYTES_COUNT; i++) {
        (*ctx).data[(*ctx).datalen] = input[i];
        (*ctx).datalen++;

        if (*ctx).datalen == 64 {
            short256_transform(ctx);

            if (*ctx).bitlen[0] > 0xffffffff - (512) {
                (*ctx).bitlen[1]++;
            }
            (*ctx).bitlen[0] += 512;


            (*ctx).datalen = 0;
        }
    }
}

fn short256_final(ctx: ptr<function, SHA256_CTX>) -> u32 {
    var i: u32 = (*ctx).datalen;

    if (*ctx).datalen < 56 {
        (*ctx).data[i] = 0x80;
        i++;
        while i < 56 {
            (*ctx).data[i] = 0x00;
            i++;
        }
    } else {
        (*ctx).data[i] = 0x80;
        i++;

        while i < 64 {
            (*ctx).data[i] = 0x00;
            i++;
        }

        short256_transform(ctx);
        for (var i = 0; i < 56 ; i++) {
            (*ctx).data[i] = 0;
        }
    }

    if (*ctx).bitlen[0] > 0xffffffff - (*ctx).datalen * 8 {
        (*ctx).bitlen[1]++;
    }

    (*ctx).bitlen[0] += (*ctx).datalen * 8;

    (*ctx).data[63] = (*ctx).bitlen[0];
    (*ctx).data[62] = (*ctx).bitlen[0] >> 8;
    (*ctx).data[61] = (*ctx).bitlen[0] >> 16;
    (*ctx).data[60] = (*ctx).bitlen[0] >> 24;
    (*ctx).data[59] = (*ctx).bitlen[1];
    (*ctx).data[58] = (*ctx).bitlen[1] >> 8;
    (*ctx).data[57] = (*ctx).bitlen[1] >> 16;
    (*ctx).data[56] = (*ctx).bitlen[1] >> 24;

    short256_transform(ctx);

    return ((*ctx).state[0] >> (24 - i * 8)) & 0x000000ff;
}

// shortened sha256. Only returns the first 4 bytes of a normal sha256 digest
// takes KIBBLE_COUNT "dense" 32 bit integers
// returns 4 "sparse" bytes, for checksum
fn short256(input: array<u32, KIBBLE_COUNT>) -> u32 {
    var ctx: SHA256_CTX;
    var buf: array<u32, BYTES_COUNT>;

    // inflate each u32 -> [u32; 4]
    for (var i = 0; i < KIBBLE_COUNT; i ++) {
        var temp = extract_bytes_be(input[i]);
        for (var j = 0; j < 4; j ++) {
            buf[(i * KIBBLE_COUNT) + j] = temp[j];
        }
    }

	// initialize context
    ctx.datalen = 0;
    ctx.bitlen[0] = 0;
    ctx.bitlen[1] = 0;
    ctx.state[0] = 0x6a09e667;
    ctx.state[1] = 0xbb67ae85;
    ctx.state[2] = 0x3c6ef372;
    ctx.state[3] = 0xa54ff53a;
    ctx.state[4] = 0x510e527f;
    ctx.state[5] = 0x9b05688c;
    ctx.state[6] = 0x1f83d9ab;
    ctx.state[7] = 0x5be0cd19;

    short256_update(&ctx, buf);
    return short256_final(&ctx);
}
