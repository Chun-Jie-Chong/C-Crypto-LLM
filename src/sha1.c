// To implement a SHA1 hash function in C, we need to define the functions declared in the given header file. Here is the implementation:

// ```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sha1.h"

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[SHA1_BLOCK_LENGTH]);

void SHA1Init(SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count = 0;
}

void SHA1Update(SHA1_CTX *context, const void *data, unsigned int len) {
    uint32_t i, j;

    j = (context->count >> 3) & 63;
    if ((context->count += len << 3) < (len << 3)) {
        context->count++;
    }
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &((const unsigned char *)data)[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &((const unsigned char *)data)[i], len - i);
}

void SHA1Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context) {
    unsigned char finalcount[8];
    unsigned char c;

    for (unsigned int i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count >> ((7 - i) * 8)) & 255);
    }
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count & 504) != 448) {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8);
    for (unsigned int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[SHA1_BLOCK_LENGTH]) {
    u_int32_t a, b, c, d, e;
    typedef union {
        unsigned char c[64];
        u_int32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16 block[1];

    memcpy(block, buffer, 64);

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+block->l[i]+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+rol(block->l[(i&15)]=rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1),5)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+rol(block->l[(i&15)]=rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1),5)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+rol(block->l[(i&15)]=rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1),5)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+rol(block->l[(i&15)]=rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1),5)+0xCA62C1D6+rol(v,5);w=rol(w,30);

    R0(a, b, c, d, e, 0); R0(e, a, b, c, d, 1); R0(d, e, a, b, c, 2); R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4); R0(a, b, c, d, e, 5); R0(e, a, b, c, d, 6); R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8); R0(b, c, d, e, a, 9); R0(a, b, c, d, e, 10); R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12); R0(c, d, e, a, b, 13); R0(b, c, d, e, a, 14); R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16); R1(d, e, a, b, c, 17); R1(c, d, e, a, b, 18); R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20); R2(e, a, b, c, d, 21); R2(d, e, a, b, c, 22); R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24); R2(a, b, c, d, e, 25); R2(e, a, b, c, d, 26); R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28); R2(b, c, d, e, a, 29); R2(a, b, c, d, e, 30); R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32); R2(c, d, e, a, b, 33); R2(b, c, d, e, a, 34); R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36); R2(d, e, a, b, c, 37); R2(c, d, e, a, b, 38); R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40); R3(e, a, b, c, d, 41); R3(d, e, a, b, c, 42); R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44); R3(a, b, c, d, e, 45); R3(e, a, b, c, d, 46); R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48); R3(b, c, d, e, a, 49); R3(a, b, c, d, e, 50); R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52); R3(c, d, e, a, b, 53); R3(b, c, d, e, a, 54); R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56); R3(d, e, a, b, c, 57); R3(c, d, e, a, b, 58); R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60); R4(e, a, b, c, d, 61); R4(d, e, a, b, c, 62); R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64); R4(a, b, c, d, e, 65); R4(e, a, b, c, d, 66); R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68); R4(b, c, d, e, a, 69); R4(a, b, c, d, e, 70); R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72); R4(c, d, e, a, b, 73); R4(b, c, d, e, a, 74); R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76); R4(d, e, a, b, c, 77); R4(c, d, e, a, b, 78); R4(b, c, d, e, a, 79);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    a = b = c = d = e = 0;
    memset(block, '\0', sizeof(block));
}
// ```

// Make sure that this code is placed in a file named `sha1.c` and the header file is named `sha1.h`.

// ### Explanation:

// 1. **Initialization (SHA1Init)**:
//    - Initializes the state and count.

// 2. **Update (SHA1Update)**:
//    - Continues accumulating data to be hashed and processing blocks of 64 bytes.

// 3. **Finalization (SHA1Final)**:
//    - Pads the remaining data to fill out a block, appends the length, and performs the final transformations.

// 4. **Transformation (SHA1Transform)**:
//    - Performs the main transformations using logical operations and rotations as per the SHA-1 algorithm.

// ### Example of how to use it:

// Here is an example file showing how to use the above implementation (`main.c`):

// ```c

void print_sha1_hash(const unsigned char * hash) {
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    SHA1_CTX ctx;
    unsigned char hash[SHA1_DIGEST_LENGTH];

    SHA1Init(&ctx);
    SHA1Update(&ctx, "Hello, world!", 13);
    SHA1Final(hash, &ctx);

    printf("SHA1 Hash: ");
    print_sha1_hash(hash);

    return 0;
}
// ```

// Compile and run the program:

// ```sh
// gcc -o sha1 sha1.c main.c
// ./sha1
// ```

// This should output the SHA1 hash for the string "Hello, world!".