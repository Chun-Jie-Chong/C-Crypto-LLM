#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

// S-box
static const uint8_t sbox[256] = {
    // The 256 elements of the S-box table go here
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
        return 1;
    }

    // Open the input file
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Failed to open input file");
        return 1;
    }

    // Determine the size of the input file
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read the file contents into a buffer
    uint8_t *input_data = malloc(file_size);
    if (!input_data) {
        perror("Failed to allocate memory");
        fclose(file);
        return 1;
    }

    fread(input_data, 1, file_size, file);
    fclose(file);

    // Example usage of AES functions (you can modify this as needed)
    AES_CTX ctx;
    uint8_t output_data[16];  // Adjust size as needed for your test

    // Set up a key (example key, replace with actual key logic)
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x88, 0x09,
        0xcf, 0x4f, 0x3c, 0x76
    };
    AES_Setkey(&ctx, key, 128);

    // Encrypt the input data
    AES_Encrypt(&ctx, input_data, output_data);

    // Generate output filename
    char output_filename[256];
    snprintf(output_filename, sizeof(output_filename), "%s_result.txt", argv[1]);

    // Open the output file in text mode
    FILE *output_file = fopen(output_filename, "w");
    if (!output_file) {
        perror("Failed to open output file");
        free(input_data);
        return 1;
    }

    // Write the encrypted data as a hex string
    fprintf(output_file, "Encrypted data: ");
    for (size_t i = 0; i < sizeof(output_data); i++) {
        fprintf(output_file, "%02x", output_data[i]);
    }
    fprintf(output_file, "\n");

    // Decrypt the data
    AES_Decrypt(&ctx, output_data, input_data);

    // Write the decrypted data as a hex string
    fprintf(output_file, "Decrypted data: ");
    for (size_t i = 0; i < sizeof(input_data); i++) {
        fprintf(output_file, "%02x", input_data[i]);
    }
    fprintf(output_file, "\n");

    // Close the output file
    fclose(output_file);

    // Free allocated memory
    free(input_data);

    return 0;
}