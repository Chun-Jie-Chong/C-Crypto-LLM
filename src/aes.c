#include <stdint.h>
#include <string.h>
#include "aes.h"

// S-box
static const uint8_t sbox[256] = {
    // The 256 elements of the S-box table go here
};

// Inverse S-box
static const uint8_t rsbox[256] = {
    // The 256 elements of the inverse S-box table go here
};

// Round constants
static const uint32_t Rcon[] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000,
    0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1b000000, 0x36000000,
    // More Rcon values as needed (there are 10 for 128-bit, 12 for 192-bit, 14 for 256-bit AES)
};

// Function prototypes for internal AES routines
static void SubBytes(uint8_t[4][4]);
static void ShiftRows(uint8_t[4][4]);
static void MixColumns(uint8_t[4][4]);
static void AddRoundKey(uint8_t[4][4], const uint32_t *);
static void InvSubBytes(uint8_t[4][4]);
static void InvShiftRows(uint8_t[4][4]);
static void InvMixColumns(uint8_t[4][4]);
static void KeyExpansion(const uint8_t *, uint32_t *, int);

// Matrix multiplication in GF(2^8)
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1)
            p ^= a;
        a = (a << 1) ^ (a & 0x80 ? 0x1b : 0);
        b >>= 1;
    }
    return p;
}

int AES_Setkey(AES_CTX *ctx, const uint8_t *key, int keysize) {
    if (ctx == NULL || key == NULL || (keysize != 128 && keysize != 192 && keysize != 256))
        return -1;

    ctx->num_rounds = 6 + keysize / 32;

    KeyExpansion(key, ctx->sk, keysize);
    KeyExpansion(key, ctx->sk_exp, keysize);  // In a real implementation, key expansion for decryption might differ

    return 0;
}

void AES_Encrypt(AES_CTX *ctx, const uint8_t *input, uint8_t *output) {
    if (ctx == NULL || input == NULL || output == NULL)
        return;

    uint8_t state[4][4];
    for (int i = 0; i < 16; i++)
        state[i % 4][i / 4] = input[i];

    AddRoundKey(state, ctx->sk);

    for (unsigned round = 1; round < ctx->num_rounds; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &ctx->sk[round * 4]);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &ctx->sk[ctx->num_rounds * 4]);

    for (int i = 0; i < 16; i++)
        output[i] = state[i % 4][i / 4];
}

void AES_Decrypt(AES_CTX *ctx, const uint8_t *input, uint8_t *output) {
    if (ctx == NULL || input == NULL || output == NULL)
        return;

    uint8_t state[4][4];
    for (int i = 0; i < 16; i++)
        state[i % 4][i / 4] = input[i];

    AddRoundKey(state, &ctx->sk[ctx->num_rounds * 4]);

    for (unsigned round = ctx->num_rounds - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, &ctx->sk[round * 4]);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, ctx->sk);

    for (int i = 0; i < 16; i++)
        output[i] = state[i % 4][i / 4];
}

void AES_Encrypt_ECB(AES_CTX *ctx, const uint8_t *input, uint8_t *output, size_t length) {
    if (ctx == NULL || input == NULL || output == NULL || length % 16 != 0)
        return;

    for (size_t i = 0; i < length; i += 16)
        AES_Encrypt(ctx, input + i, output + i);
}

void AES_Decrypt_ECB(AES_CTX *ctx, const uint8_t *input, uint8_t *output, size_t length) {
    if (ctx == NULL || input == NULL || output == NULL || length % 16 != 0)
        return;

    for (size_t i = 0; i < length; i += 16)
        AES_Decrypt(ctx, input + i, output + i);
}

int AES_KeySetup_Encrypt(uint32_t *sk, const uint8_t *key, int keysize) {
    KeyExpansion(key, sk, keysize);
    return 0;
}

int AES_KeySetup_Decrypt(uint32_t *sk, const uint8_t *key, int keysize) {
    KeyExpansion(key, sk, keysize);  // In a real implementation, key expansion for decryption might differ
    return 0;
}

// Internal AES routines

static void SubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];
}

static void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

static void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = gmul(state[0][i], 0x02) ^ gmul(state[1][i], 0x03) ^ state[2][i] ^ state[3][i];
        temp[1] = state[0][i] ^ gmul(state[1][i], 0x02) ^ gmul(state[2][i], 0x03) ^ state[3][i];
        temp[2] = state[0][i] ^ state[1][i] ^ gmul(state[2][i], 0x02) ^ gmul(state[3][i], 0x03);
        temp[3] = gmul(state[0][i], 0x03) ^ state[1][i] ^ state[2][i] ^ gmul(state[3][i], 0x02);
        state[0][i] = temp[0];
        state[1][i] = temp[1];
        state[2][i] = temp[2];
        state[3][i] = temp[3];
    }
}

static void AddRoundKey(uint8_t state[4][4], const uint32_t *roundKey) {
    for (int i = 0; i < 4; i++) {
        state[0][i] ^= (roundKey[i] >> 24) & 0xff;
        state[1][i] ^= (roundKey[i] >> 16) & 0xff;
        state[2][i] ^= (roundKey[i] >> 8) & 0xff;
        state[3][i] ^= roundKey[i] & 0xff;
    }
}

static void InvSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = rsbox[state[i][j]];
}

static void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

static void InvMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = gmul(state[0][i], 0x0e) ^ gmul(state[1][i], 0x0b) ^ gmul(state[2][i], 0x0d) ^ gmul(state[3][i], 0x09);
        temp[1] = gmul(state[0][i], 0x09) ^ gmul(state[1][i], 0x0e) ^ gmul(state[2][i], 0x0b) ^ gmul(state[3][i], 0x0d);
        temp[2] = gmul(state[0][i], 0x0d) ^ gmul(state[1][i], 0x09) ^ gmul(state[2][i], 0x0e) ^ gmul(state[3][i], 0x0b);
        temp[3] = gmul(state[0][i], 0x0b) ^ gmul(state[1][i], 0x0d) ^ gmul(state[2][i], 0x09) ^ gmul(state[3][i], 0x0e);
        state[0][i] = temp[0];
        state[1][i] = temp[1];
        state[2][i] = temp[2];
        state[3][i] = temp[3];
    }
}

static void KeyExpansion(const uint8_t *key, uint32_t *w, int keysize) {
    uint32_t temp;
    int i = 0;
    const int Nk = keysize / 32;
    const int Nr = Nk + 6;

    for (i = 0; i < Nk; i++) {
        w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | (key[4 * i + 3]);
    }

    for (i = Nk; i < 4 * (Nr + 1); i++) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            temp = (sbox[(temp >> 16) & 0xff] << 24) | (sbox[(temp >> 8) & 0xff] << 16) | 
                   (sbox[temp & 0xff] << 8) | (sbox[(temp >> 24)] );
            temp ^= Rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = (sbox[temp >> 24] << 24) | (sbox[(temp >> 16) & 0xff] << 16) |
                   (sbox[(temp >> 8) & 0xff] << 8) | sbox[temp & 0xff];
        }
        w[i] = w[i - Nk] ^ temp;
    }
}