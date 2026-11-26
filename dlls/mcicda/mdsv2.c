/*
 * DAEMON Tools MDS version 2 descriptors
 *
 * Version 2 descriptors are zlib compressed and AES-256 encrypted with a key that is derived
 * from data stored in the file itself (TrueCrypt style header: PBKDF2 with RIPEMD-160).
 * The layout follows CDemu's libmirage MDX parser. The decoded descriptor is rewritten in
 * the version 1 layout, so the code reading Alcohol 120% descriptors handles both.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mdsv2.h"

#define MDS_V2_FILE_HEADER_SIZE 48
#define MDS_V2_CRYPT_HEADER_SIZE 512
#define MDS_V2_SALT_SIZE 64
#define MDS_V2_KEY_SIZE 256
#define MDS_V2_MAGIC 0x54525545 /* "TRUE" */
#define MDS_V2_SESSION_SIZE 32
#define MDS_V1_SESSION_SIZE 24
#define MDS_TRACK_SIZE 80
#define MDS_MAX_DESCRIPTOR (16 * 1024 * 1024)

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t rol32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* RIPEMD-160 */

typedef struct {
    uint32_t h[5];
    uint64_t length;
    uint8_t buffer[64];
    unsigned int used;
} rmd160_ctx;

static const uint8_t rmd_rl[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
};

static const uint8_t rmd_rr[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
};

static const uint8_t rmd_sl[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
};

static const uint8_t rmd_sr[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
};

static uint32_t rmd_f(int j, uint32_t x, uint32_t y, uint32_t z)
{
    switch (j / 16) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
    }
}

static void rmd160_block(rmd160_ctx *ctx, const uint8_t *block)
{
    static const uint32_t kl[5] = { 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };
    static const uint32_t kr[5] = { 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };
    uint32_t x[16], al, bl, cl, dl, el, ar, br, cr, dr, er, t;
    int j;

    for (j = 0; j < 16; j++) x[j] = rd32(block + j * 4);

    al = ar = ctx->h[0];
    bl = br = ctx->h[1];
    cl = cr = ctx->h[2];
    dl = dr = ctx->h[3];
    el = er = ctx->h[4];

    for (j = 0; j < 80; j++) {
        t = rol32(al + rmd_f(j, bl, cl, dl) + x[rmd_rl[j]] + kl[j / 16], rmd_sl[j]) + el;
        al = el; el = dl; dl = rol32(cl, 10); cl = bl; bl = t;
        t = rol32(ar + rmd_f(79 - j, br, cr, dr) + x[rmd_rr[j]] + kr[j / 16], rmd_sr[j]) + er;
        ar = er; er = dr; dr = rol32(cr, 10); cr = br; br = t;
    }

    t = ctx->h[1] + cl + dr;
    ctx->h[1] = ctx->h[2] + dl + er;
    ctx->h[2] = ctx->h[3] + el + ar;
    ctx->h[3] = ctx->h[4] + al + br;
    ctx->h[4] = ctx->h[0] + bl + cr;
    ctx->h[0] = t;
}

static void rmd160_init(rmd160_ctx *ctx)
{
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xc3d2e1f0;
    ctx->length = 0;
    ctx->used = 0;
}

static void rmd160_update(rmd160_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->length += len;
    while (len) {
        size_t n = 64 - ctx->used;
        if (n > len) n = len;
        memcpy(ctx->buffer + ctx->used, data, n);
        ctx->used += (unsigned int)n;
        data += n;
        len -= n;
        if (ctx->used == 64) {
            rmd160_block(ctx, ctx->buffer);
            ctx->used = 0;
        }
    }
}

static void rmd160_final(rmd160_ctx *ctx, uint8_t *digest)
{
    uint64_t bits = ctx->length * 8;
    uint8_t pad = 0x80, zero = 0, size[8];
    int i;

    for (i = 0; i < 8; i++) size[i] = (uint8_t)(bits >> (8 * i));
    rmd160_update(ctx, &pad, 1);
    while (ctx->used != 56) rmd160_update(ctx, &zero, 1);
    rmd160_update(ctx, size, 8);
    for (i = 0; i < 5; i++) wr32(digest + i * 4, ctx->h[i]);
}

/* PBKDF2 with HMAC-RIPEMD-160 */
static void pbkdf2_rmd160(const uint8_t *password, size_t passwordLen, const uint8_t *salt, size_t saltLen,
                          unsigned int iterations, uint8_t *out, size_t outLen)
{
    uint8_t ipad[64], opad[64], u[20], t[20], counter[4];
    rmd160_ctx inner, outer, ctx;
    uint32_t block = 1;
    unsigned int i, k;

    /* the passwords used here are at most 64 bytes, the HMAC block size */
    memset(ipad, 0x36, sizeof(ipad));
    memset(opad, 0x5c, sizeof(opad));
    for (i = 0; i < passwordLen && i < 64; i++) {
        ipad[i] ^= password[i];
        opad[i] ^= password[i];
    }
    rmd160_init(&inner);
    rmd160_update(&inner, ipad, 64);
    rmd160_init(&outer);
    rmd160_update(&outer, opad, 64);

    while (outLen) {
        size_t n = outLen < 20 ? outLen : 20;

        counter[0] = (uint8_t)(block >> 24);
        counter[1] = (uint8_t)(block >> 16);
        counter[2] = (uint8_t)(block >> 8);
        counter[3] = (uint8_t)block;

        ctx = inner;
        rmd160_update(&ctx, salt, saltLen);
        rmd160_update(&ctx, counter, 4);
        rmd160_final(&ctx, u);
        ctx = outer;
        rmd160_update(&ctx, u, 20);
        rmd160_final(&ctx, u);
        memcpy(t, u, 20);

        for (i = 1; i < iterations; i++) {
            ctx = inner;
            rmd160_update(&ctx, u, 20);
            rmd160_final(&ctx, u);
            ctx = outer;
            rmd160_update(&ctx, u, 20);
            rmd160_final(&ctx, u);
            for (k = 0; k < 20; k++) t[k] ^= u[k];
        }

        memcpy(out, t, n);
        out += n;
        outLen -= n;
        block++;
    }
}

/* AES-256 decryption */

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

typedef struct {
    uint8_t roundKeys[15 * 16];
    uint8_t invSbox[256];
} aes256_ctx;

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;

    while (b) {
        if (b & 1) r ^= a;
        a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
        b >>= 1;
    }
    return r;
}

static void aes256_init(aes256_ctx *ctx, const uint8_t *key)
{
    uint8_t *w = ctx->roundKeys, rcon = 1, t[4];
    int i;

    for (i = 0; i < 256; i++) ctx->invSbox[aes_sbox[i]] = (uint8_t)i;

    memcpy(w, key, 32);
    for (i = 8; i < 60; i++) {
        memcpy(t, w + (i - 1) * 4, 4);
        if (i % 8 == 0) {
            uint8_t first = t[0];
            t[0] = aes_sbox[t[1]] ^ rcon;
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[first];
            rcon = gf_mul(rcon, 2);
        }
        else if (i % 8 == 4) {
            t[0] = aes_sbox[t[0]];
            t[1] = aes_sbox[t[1]];
            t[2] = aes_sbox[t[2]];
            t[3] = aes_sbox[t[3]];
        }
        w[i * 4 + 0] = w[(i - 8) * 4 + 0] ^ t[0];
        w[i * 4 + 1] = w[(i - 8) * 4 + 1] ^ t[1];
        w[i * 4 + 2] = w[(i - 8) * 4 + 2] ^ t[2];
        w[i * 4 + 3] = w[(i - 8) * 4 + 3] ^ t[3];
    }
}

static void aes256_decrypt_block(const aes256_ctx *ctx, uint8_t *s)
{
    uint8_t t[16];
    int round, i, c;

    for (i = 0; i < 16; i++) s[i] ^= ctx->roundKeys[14 * 16 + i];

    for (round = 13; round >= 0; round--) {
        /* inverse shift rows (state is column major) and inverse substitution */
        for (c = 0; c < 4; c++)
            for (i = 0; i < 4; i++) t[c * 4 + i] = ctx->invSbox[s[((c - i + 4) % 4) * 4 + i]];
        for (i = 0; i < 16; i++) s[i] = t[i] ^ ctx->roundKeys[round * 16 + i];
        if (!round) break;

        /* inverse mix columns */
        for (c = 0; c < 4; c++) {
            uint8_t a0 = s[c * 4], a1 = s[c * 4 + 1], a2 = s[c * 4 + 2], a3 = s[c * 4 + 3];
            s[c * 4 + 0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
            s[c * 4 + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
            s[c * 4 + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
            s[c * 4 + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
        }
    }
}

/* TrueCrypt's legacy CBC: every block is also XORed with the second half of the IV
 * ("whitening") before it is deciphered */
static void decrypt_cbc_whitened(const uint8_t *key, const uint8_t *iv, uint8_t *data, size_t len)
{
    uint8_t chain[16], cipher[16];
    aes256_ctx ctx;
    size_t pos;
    int i;

    aes256_init(&ctx, key);
    memcpy(chain, iv, 16);

    for (pos = 0; pos + 16 <= len; pos += 16) {
        uint8_t *block = data + pos;

        for (i = 0; i < 16; i++) block[i] ^= iv[8 + i % 8];
        memcpy(cipher, block, 16);
        aes256_decrypt_block(&ctx, block);
        for (i = 0; i < 16; i++) block[i] ^= chain[i];
        memcpy(chain, cipher, 16);
    }
}

/* CRC-32 */
static uint32_t crc32_reflected(const uint8_t *data, size_t len, uint32_t poly, uint32_t init, uint32_t xorOut)
{
    uint32_t crc = init;
    size_t i;
    int b;

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (b = 0; b < 8; b++) crc = (crc >> 1) ^ ((crc & 1) ? poly : 0);
    }
    return crc ^ xorOut;
}

/* zlib inflate */

typedef struct {
    const uint8_t *in;
    size_t inLen, inPos;
    uint32_t bits;
    int bitCount;
    uint8_t *out;
    size_t outLen, outPos;
    int error;
} inflate_state;

typedef struct {
    uint16_t counts[16];
    uint16_t symbols[288];
} huffman;

static unsigned int get_bits(inflate_state *s, int n)
{
    unsigned int v;

    while (s->bitCount < n) {
        if (s->inPos >= s->inLen) {
            s->error = 1;
            return 0;
        }
        s->bits |= (uint32_t)s->in[s->inPos++] << s->bitCount;
        s->bitCount += 8;
    }
    v = s->bits & ((1u << n) - 1);
    s->bits >>= n;
    s->bitCount -= n;
    return v;
}

static int build_huffman(huffman *h, const uint8_t *lengths, int n)
{
    uint16_t offsets[16];
    int i, left = 1;

    memset(h->counts, 0, sizeof(h->counts));
    for (i = 0; i < n; i++) h->counts[lengths[i]]++;
    h->counts[0] = 0;
    for (i = 1; i < 16; i++) {
        left = (left << 1) - h->counts[i];
        if (left < 0) return 0;
    }
    offsets[1] = 0;
    for (i = 1; i < 15; i++) offsets[i + 1] = offsets[i] + h->counts[i];
    for (i = 0; i < n; i++)
        if (lengths[i]) h->symbols[offsets[lengths[i]]++] = (uint16_t)i;
    return 1;
}

static int decode_symbol(inflate_state *s, const huffman *h)
{
    int code = 0, first = 0, index = 0, len;

    for (len = 1; len < 16; len++) {
        code |= (int)get_bits(s, 1);
        if (s->error) return -1;
        if (code - h->counts[len] < first) return h->symbols[index + (code - first)];
        index += h->counts[len];
        first = (first + h->counts[len]) << 1;
        code <<= 1;
    }
    s->error = 1;
    return -1;
}

static int inflate_codes(inflate_state *s, const huffman *lit, const huffman *dist)
{
    static const uint16_t lenBase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                          35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    static const uint8_t lenExtra[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                                          3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    static const uint16_t distBase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
                                           193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
                                           6145, 8193, 12289, 16385, 24577 };
    static const uint8_t distExtra[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                                           7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

    for (;;) {
        int sym = decode_symbol(s, lit);
        size_t len, d;

        if (sym < 0) return 0;
        if (sym < 256) {
            if (s->outPos >= s->outLen) return 0;
            s->out[s->outPos++] = (uint8_t)sym;
            continue;
        }
        if (sym == 256) return 1;

        sym -= 257;
        if (sym >= 29) return 0;
        len = lenBase[sym] + get_bits(s, lenExtra[sym]);
        sym = decode_symbol(s, dist);
        if (sym < 0 || sym >= 30) return 0;
        d = distBase[sym] + get_bits(s, distExtra[sym]);
        if (s->error || d > s->outPos || len > s->outLen - s->outPos) return 0;
        while (len--) {
            s->out[s->outPos] = s->out[s->outPos - d];
            s->outPos++;
        }
    }
}

static int inflate_dynamic(inflate_state *s)
{
    static const uint8_t order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    uint8_t lengths[320];
    huffman lit, dist;
    int nlen, ndist, ncode, i;

    nlen = (int)get_bits(s, 5) + 257;
    ndist = (int)get_bits(s, 5) + 1;
    ncode = (int)get_bits(s, 4) + 4;
    if (s->error || nlen > 286 || ndist > 30) return 0;

    memset(lengths, 0, sizeof(lengths));
    for (i = 0; i < ncode; i++) lengths[order[i]] = (uint8_t)get_bits(s, 3);
    if (s->error || !build_huffman(&lit, lengths, 19)) return 0;

    for (i = 0; i < nlen + ndist;) {
        int sym = decode_symbol(s, &lit), repeat;
        uint8_t value = 0;

        if (sym < 0) return 0;
        if (sym < 16) {
            lengths[i++] = (uint8_t)sym;
            continue;
        }
        if (sym == 16) {
            if (!i) return 0;
            value = lengths[i - 1];
            repeat = 3 + (int)get_bits(s, 2);
        }
        else if (sym == 17) repeat = 3 + (int)get_bits(s, 3);
        else repeat = 11 + (int)get_bits(s, 7);
        if (s->error || i + repeat > nlen + ndist) return 0;
        while (repeat--) lengths[i++] = value;
    }

    if (!lengths[256] || !build_huffman(&lit, lengths, nlen) || !build_huffman(&dist, lengths + nlen, ndist))
        return 0;
    return inflate_codes(s, &lit, &dist);
}

static int inflate_fixed(inflate_state *s)
{
    uint8_t lengths[320];
    huffman lit, dist;
    int i;

    for (i = 0; i < 144; i++) lengths[i] = 8;
    for (; i < 256; i++) lengths[i] = 9;
    for (; i < 280; i++) lengths[i] = 7;
    for (; i < 288; i++) lengths[i] = 8;
    for (; i < 288 + 30; i++) lengths[i] = 5;
    build_huffman(&lit, lengths, 288);
    build_huffman(&dist, lengths + 288, 30);
    return inflate_codes(s, &lit, &dist);
}

static int inflate_stored(inflate_state *s)
{
    unsigned int len;

    s->bits = 0;
    s->bitCount = 0;
    if (s->inPos + 4 > s->inLen) return 0;
    len = s->in[s->inPos] | (s->in[s->inPos + 1] << 8);
    if ((len ^ 0xffff) != (unsigned int)(s->in[s->inPos + 2] | (s->in[s->inPos + 3] << 8))) return 0;
    s->inPos += 4;
    if (len > s->inLen - s->inPos || len > s->outLen - s->outPos) return 0;
    memcpy(s->out + s->outPos, s->in + s->inPos, len);
    s->inPos += len;
    s->outPos += len;
    return 1;
}

/* returns the number of bytes written, or 0 on error */
static size_t zlib_inflate(const uint8_t *in, size_t inLen, uint8_t *out, size_t outLen)
{
    inflate_state s;
    int last;

    if (inLen < 2 || (in[0] & 0x0f) != 8 || ((in[0] << 8) | in[1]) % 31 || (in[1] & 0x20))
        return 0;

    memset(&s, 0, sizeof(s));
    s.in = in;
    s.inLen = inLen;
    s.inPos = 2;
    s.out = out;
    s.outLen = outLen;

    do {
        int ok;

        last = (int)get_bits(&s, 1);
        switch (get_bits(&s, 2)) {
        case 0: ok = inflate_stored(&s); break;
        case 1: ok = inflate_fixed(&s); break;
        case 2: ok = inflate_dynamic(&s); break;
        default: ok = 0; break;
        }
        if (!ok || s.error) return 0;
    } while (!last);

    return s.outPos;
}

/* The header key is derived from a password that is itself computed from the salt */
static void header_password(const uint8_t *salt, uint8_t *password)
{
    uint32_t modifier = crc32_reflected(salt, MDS_V2_SALT_SIZE, 0xd8018001, 0, 0) ^ 0x567372ff;
    int i, b;

    for (i = 0; i < MDS_V2_SALT_SIZE / 4; i++) {
        uint32_t value;

        modifier = modifier * 0x35e85a6d + 0x1548dce9;
        value = rd32(salt + i * 4) ^ modifier ^ 0xec564717;
        for (b = 0; b < 4; b++)
            if (!(value & (0xffu << (b * 8)))) value |= 0x5fu << (b * 8);
        wr32(password + i * 4, value);
    }
}

/* the decoded descriptor, with the 18 signature and version bytes in front of it: the offsets
 * inside it count them */
static uint8_t *decrypt_descriptor(const uint8_t *mds, size_t size, size_t *outSize)
{
    uint8_t header[MDS_V2_CRYPT_HEADER_SIZE], masterKey[160], password[MDS_V2_SALT_SIZE];
    uint8_t *key, *encrypted, *descriptor;
    uint32_t headerOffset, compressedSize, decompressedSize;
    size_t encryptedSize, pos;

    if (size < MDS_V2_FILE_HEADER_SIZE) return NULL;
    headerOffset = rd32(mds + 0x2c);
    /* 0xffffffff: an MDX file, which keeps the descriptor at its end; not handled */
    if (headerOffset < MDS_V2_FILE_HEADER_SIZE || headerOffset > size || size - headerOffset < MDS_V2_CRYPT_HEADER_SIZE)
        return NULL;

    memcpy(header, mds + headerOffset, sizeof(header));
    header_password(header, password);
    pbkdf2_rmd160(password, sizeof(password), header, MDS_V2_SALT_SIZE, 2000, masterKey, 120 + 32);
    decrypt_cbc_whitened(masterKey + 32, masterKey, header + MDS_V2_SALT_SIZE,
                         MDS_V2_CRYPT_HEADER_SIZE - MDS_V2_SALT_SIZE);

    /* deciphered: checksum, magic, ?, key size, ?, key data, compressed size, decompressed size */
    key = header + MDS_V2_SALT_SIZE + 16;
    if (rd32(header + MDS_V2_SALT_SIZE + 4) != MDS_V2_MAGIC || rd16(header + MDS_V2_SALT_SIZE + 10) != MDS_V2_KEY_SIZE ||
        rd32(header + MDS_V2_SALT_SIZE) != crc32_reflected(key, MDS_V2_KEY_SIZE, 0xedb88320, 0xffffffff, 0xffffffff))
        return NULL;

    compressedSize = rd32(key + MDS_V2_KEY_SIZE);
    decompressedSize = rd32(key + MDS_V2_KEY_SIZE + 4);
    encryptedSize = headerOffset - MDS_V2_FILE_HEADER_SIZE;
    if (!compressedSize || compressedSize > encryptedSize || encryptedSize % 16 || encryptedSize - compressedSize >= 16 ||
        !decompressedSize || decompressedSize > MDS_MAX_DESCRIPTOR)
        return NULL;

    if (!(encrypted = malloc(encryptedSize))) return NULL;
    memcpy(encrypted, mds + MDS_V2_FILE_HEADER_SIZE, encryptedSize);
    /* TrueCrypt sectors: the chain restarts every 512 bytes */
    for (pos = 0; pos < encryptedSize; pos += 512)
        decrypt_cbc_whitened(key + 32, key, encrypted + pos, encryptedSize - pos < 512 ? encryptedSize - pos : 512);

    descriptor = calloc(1, decompressedSize + 18);
    if (descriptor && zlib_inflate(encrypted, compressedSize, descriptor + 18, decompressedSize) != decompressedSize) {
        free(descriptor);
        descriptor = NULL;
    }
    free(encrypted);

    if (descriptor) {
        memcpy(descriptor, mds, 18);
        *outSize = decompressedSize + 18;
    }
    return descriptor;
}

uint8_t *mdsv2_to_v1(const uint8_t *mds, size_t size, size_t *outSize)
{
    uint8_t *d;
    size_t dsize = 0;
    uint16_t sessionCount, s;
    uint32_t sessionsOffset;

    if (size < 18 || memcmp(mds, "MEDIA DESCRIPTOR", 16) || mds[16] != 2) return NULL;
    if (!(d = decrypt_descriptor(mds, size, &dsize))) return NULL;
    if (dsize < 0x58) goto fail;

    sessionCount = rd16(d + 0x14);
    sessionsOffset = rd32(d + 0x50);
    if (sessionsOffset > dsize || (dsize - sessionsOffset) / MDS_V2_SESSION_SIZE < sessionCount) goto fail;

    d[16] = 1;
    d[17] = 5;
    /* medium type: version 2 uses 0 for CD-ROM and 3 for DVD-ROM, version 1 uses 0x10 and up for DVDs */
    d[0x12] = rd16(d + 0x12) >= 3 ? 0x10 : 0x00;
    d[0x13] = 0;

    for (s = 0; s < sessionCount; s++) {
        const uint8_t *v2 = d + sessionsOffset + s * MDS_V2_SESSION_SIZE;
        uint8_t *v1 = d + sessionsOffset + s * MDS_V1_SESSION_SIZE;
        uint32_t start = rd32(v2), end = rd32(v2 + 24), tracksOffset = rd32(v2 + 20);
        uint8_t blockCount = v2[10], b, rest[12];

        /* the version 1 block is shorter, and it is written over the start of this one */
        memcpy(rest, v2 + 8, sizeof(rest));
        wr32(v1, start);
        wr32(v1 + 4, end);
        memcpy(v1 + 8, rest, sizeof(rest));
        wr32(v1 + 20, tracksOffset);

        if (tracksOffset > dsize || (dsize - tracksOffset) / MDS_TRACK_SIZE < blockCount) goto fail;

        for (b = 0; b < blockCount; b++) {
            uint8_t *track = d + tracksOffset + b * MDS_TRACK_SIZE;
            uint32_t footerOffset = rd32(track + 52);
            static const uint8_t modes[8] = { 0x00, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0x00, 0x00 };

            if (track[4] == 0 || track[4] > 99) continue; /* lead-in entries */

            /* sector type in the low 3 bits; the sector size is always given */
            track[0] = modes[track[0] & 7];
            track[1] = 0;
            /* the track's LBA is only in the 64-bit field */
            wr32(track + 36, rd32(track + 56));
            /* file names are always wide */
            if (footerOffset && footerOffset <= dsize - 8) wr32(d + footerOffset + 4, 1);
        }
    }

    *outSize = dsize;
    return d;

fail:
    free(d);
    return NULL;
}
