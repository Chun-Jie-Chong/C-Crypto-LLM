// Sure, here's an implementation of the MD5 hash function in C based on the provided header file. The implementation closely follows the RFC 1321 specification of MD5.

// First, you should include necessary headers:

// ```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
// ```

// Here is the implementation:

// ```c
#include "md5.h"

// Constants for MD5Transform routine.
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static uint8_t PADDING[64] = {
  0x80
};

// static void MD5Transform(uint32_t state[4], const uint8_t block[MD5_BLOCK_LENGTH]);
static void Encode(uint8_t *output, const uint32_t *input, size_t len);
static void Decode(uint32_t *output, const uint8_t *input, size_t len);

void MD5Init(MD5_CTX *context) {
  context->count = 0;
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

void MD5Update(MD5_CTX *context, const void *input, size_t len) {
  size_t i, index, partLen;

  index = (size_t)((context->count >> 3) & 0x3F);
  context->count += ((uint64_t)len << 3);

  partLen = 64 - index;

  if (len >= partLen) {
    memcpy(&context->buffer[index], input, partLen);
    MD5Transform(context->state, context->buffer);

    for (i = partLen; i + 63 < len; i += 64)
      MD5Transform(context->state, (const uint8_t *)input + i);

    index = 0;
  }
  else {
    i = 0;
  }

  memcpy(&context->buffer[index], (const uint8_t *)input + i, len - i);
}

void MD5Final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *context) {
  uint8_t bits[8];
  size_t index, padLen;

  Encode(bits, &context->count, 8);

  index = (size_t)((context->count >> 3) & 0x3F);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update(context, PADDING, padLen);

  MD5Update(context, bits, 8);

  Encode(digest, context->state, MD5_DIGEST_LENGTH);

  memset(context, 0, sizeof(*context));
}

void MD5Transform(uint32_t state[4], const uint8_t block[MD5_BLOCK_LENGTH]) {
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode(x, block, MD5_BLOCK_LENGTH);

    // Round 1
  #define FF(a, b, c, d, x, s, ac) { \
    a += ((b & c) | (~b & d)) + x + ac; \
    a = ((a << s) | ((a & 0xffffffff) >> (32-s))); \
    a += b; \
  }
  FF(a, b, c, d, x[ 0], S11, 0xd76aa478);
  FF(d, a, b, c, x[ 1], S12, 0xe8c7b756);
  FF(c, d, a, b, x[ 2], S13, 0x242070db);
  FF(b, c, d, a, x[ 3], S14, 0xc1bdceee);
  FF(a, b, c, d, x[ 4], S11, 0xf57c0faf);
  FF(d, a, b, c, x[ 5], S12, 0x4787c62a);
  FF(c, d, a, b, x[ 6], S13, 0xa8304613);
  FF(b, c, d, a, x[ 7], S14, 0xfd469501);
  FF(a, b, c, d, x[ 8], S11, 0x698098d8);
  FF(d, a, b, c, x[ 9], S12, 0x8b44f7af);
  FF(c, d, a, b, x[10], S13, 0xffff5bb1);
  FF(b, c, d, a, x[11], S14, 0x895cd7be);
  FF(a, b, c, d, x[12], S11, 0x6b901122);
  FF(d, a, b, c, x[13], S12, 0xfd987193);
  FF(c, d, a, b, x[14], S13, 0xa679438e);
  FF(b, c, d, a, x[15], S14, 0x49b40821);

    // Round 2
  #define GG(a, b, c, d, x, s, ac) { \
    a += ((b & d) | (c & ~d)) + x + ac; \
    a = ((a << s) | ((a & 0xffffffff) >> (32-s))); \
    a += b; \
  }
  GG(a, b, c, d, x[ 1], S21, 0xf61e2562);
  GG(d, a, b, c, x[ 6], S22, 0xc040b340);
  GG(c, d, a, b, x[11], S23, 0x265e5a51);
  GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
  GG(a, b, c, d, x[ 5], S21, 0xd62f105d);
  GG(d, a, b, c, x[10], S22, 0x02441453);
  GG(c, d, a, b, x[15], S23, 0xd8a1e681);
  GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8);
  GG(a, b, c, d, x[ 9], S21, 0x21e1cde6);
  GG(d, a, b, c, x[14], S22, 0xc33707d6);
  GG(c, d, a, b, x[ 3], S23, 0xf4d50d87);
  GG(b, c, d, a, x[ 8], S24, 0x455a14ed);
  GG(a, b, c, d, x[13], S21, 0xa9e3e905);
  GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8);
  GG(c, d, a, b, x[ 7], S23, 0x676f02d9);
  GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

    // Round 3
  #define HH(a, b, c, d, x, s, ac) { \
    a += (b ^ c ^ d) + x + ac; \
    a = ((a << s) | ((a & 0xffffffff) >> (32-s))); \
    a += b; \
  }
  HH(a, b, c, d, x[ 5], S31, 0xfffa3942);
  HH(d, a, b, c, x[ 8], S32, 0x8771f681);
  HH(c, d, a, b, x[11], S33, 0x6d9d6122);
  HH(b, c, d, a, x[14], S34, 0xfde5380c);
  HH(a, b, c, d, x[ 1], S31, 0xa4beea44);
  HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9);
  HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60);
  HH(b, c, d, a, x[10], S34, 0xbebfbc70);
  HH(a, b, c, d, x[13], S31, 0x289b7ec6);
  HH(d, a, b, c, x[ 0], S32, 0xeaa127fa);
  HH(c, d, a, b, x[ 3], S33, 0xd4ef3085);
  HH(b, c, d, a, x[ 6], S34, 0x04881d05);
  HH(a, b, c, d, x[ 9], S31, 0xd9d4d039);
  HH(d, a, b, c, x[12], S32, 0xe6db99e5);
  HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
  HH(b, c, d, a, x[ 2], S34, 0xc4ac5665);

    // Round 4
  #define II(a, b, c, d, x, s, ac) { \
    a += (c ^ (b | ~d)) + x + ac; \
    a = ((a << s) | ((a & 0xffffffff) >> (32-s))); \
    a += b; \
  }
  II(a, b, c, d, x[ 0], S41, 0xf4292244);
  II(d, a, b, c, x[ 7], S42, 0x432aff97);
  II(c, d, a, b, x[14], S43, 0xab9423a7);
  II(b, c, d, a, x[ 5], S44, 0xfc93a039);
  II(a, b, c, d, x[12], S41, 0x655b59c3);
  II(d, a, b, c, x[ 3], S42, 0x8f0ccc92);
  II(c, d, a, b, x[10], S43, 0xffeff47d);
  II(b, c, d, a, x[ 1], S44, 0x85845dd1);
  II(a, b, c, d, x[ 8], S41, 0x6fa87e4f);
  II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
  II(c, d, a, b, x[ 6], S43, 0xa3014314);
  II(b, c, d, a, x[13], S44, 0x4e0811a1);
  II(a, b, c, d, x[ 4], S41, 0xf7537e82);
  II(d, a, b, c, x[11], S42, 0xbd3af235);
  II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb);
  II(b, c, d, a, x[ 9], S44, 0xeb86d391);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  memset(x, 0, sizeof(x));
}

static void Encode(uint8_t *output, const uint32_t *input, size_t len) {
  size_t i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (uint8_t)(input[i] & 0xff);
    output[j + 1] = (uint8_t)((input[i] >> 8) & 0xff);
    output[j + 2] = (uint8_t)((input[i] >> 16) & 0xff);
    output[j + 3] = (uint8_t)((input[i] >> 24) & 0xff);
  }
}

static void Decode(uint32_t *output, const uint8_t *input, size_t len) {
  size_t i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
                (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
  }
}

void compute_md5(const unsigned char *data, size_t length, unsigned char digest[MD5_DIGEST_LENGTH]) {
    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, data, length);
    MD5Final(digest, &ctx);
}

// Function to print MD5 hash as a hex string
void print_md5(const unsigned char digest[MD5_DIGEST_LENGTH]) {

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// Function to convert binary data to hex string
void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02x", bin[i]);
    }
    hex[2 * len] = '\0';  // Null-terminate the string
}

// Test known MD5 vectors
void test_md5_known_vectors() {
    // Define test vectors (input and expected MD5 hash)
    const char *test_inputs[] = {
        "abc",
        "hello, world",
        "The quick brown fox jumps over the lazy dog"
    };
    
    const char *expected_hashes[] = {
        "900150983cd24fb0d6963f7d28e17f72",
        "e4d7f1b4ed2e42d15898f4b27b019da4",
        "9e107d9d372bb6826bd81d3542a419d6"
    };
    
    // Number of test vectors
    size_t num_tests = sizeof(test_inputs) / sizeof(test_inputs[0]);
    
    for (size_t i = 0; i < num_tests; i++) {
        unsigned char digest[MD5_DIGEST_LENGTH];
        compute_md5((unsigned char *)test_inputs[i], strlen(test_inputs[i]), digest);
        
        printf("Input: \"%s\"\n", test_inputs[i]);
        printf("Expected MD5: %s\n", expected_hashes[i]);
        printf("Computed MD5: ");
        print_md5(digest);

        // Convert binary digest to hex string
        char result[2 * MD5_DIGEST_LENGTH + 1];
        bin_to_hex(digest, MD5_DIGEST_LENGTH, result);

        if (strcmp(result, expected_hashes[i]) == 0) {
            printf("Test passed\n\n");
        } else {
            printf("Test failed\n\n");
        }
    }
}

int main() {
    test_md5_known_vectors();
    return 0;
}

// int main(int argc, char *argv[]) {
//     if (argc != 2) {
//         fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
//         return 1;
//     }

//     FILE *file = fopen(argv[1], "rb");
//     if (!file) {
//         perror("Failed to open input file");
//         return 1;
//     }

//     // Determine file size
//     fseek(file, 0, SEEK_END);
//     long file_size = ftell(file);
//     fseek(file, 0, SEEK_SET);

//     // Allocate buffer to read file data
//     unsigned char *input_data = malloc(file_size);
//     if (!input_data) {
//         perror("Failed to allocate memory");
//         fclose(file);
//         return 1;
//     }

//     fread(input_data, 1, file_size, file);
//     fclose(file);

//     // Compute MD5 of the input data
//     unsigned char original_md5[MD5_DIGEST_LENGTH];
//     compute_md5(input_data, file_size, original_md5);

//     // Encode the data (Placeholder, replace with actual encoding logic)
//     unsigned char *encoded_data = malloc(file_size);  // Assuming same size after encoding
//     Encode(encoded_data, (const uint32_t *)input_data, file_size);

//     // Decode the data (Placeholder, replace with actual decoding logic)
//     unsigned char *decoded_data = malloc(file_size);
//     Decode((uint32_t *)decoded_data, (const uint8_t *)encoded_data, file_size);

//     // Compute MD5 of the decoded data
//     unsigned char decoded_md5[MD5_DIGEST_LENGTH];
//     compute_md5(decoded_data, file_size, decoded_md5);

//     // Create output file name with "_result.txt" appended
//     char result_filename[256];
//     snprintf(result_filename, sizeof(result_filename), "%s_result.txt", argv[1]);

//     // Open the result file for writing
//     FILE *result_file = fopen(result_filename, "w");
//     if (!result_file) {
//         perror("Failed to open result file");
//         free(input_data);
//         free(encoded_data);
//         free(decoded_data);
//         return 1;
//     }

//     // Write the input, encoded, decoded data, and MD5 checksums to the result file
//     fprintf(result_file, "Input Data:\n");
//     fwrite(input_data, 1, file_size, result_file);
//     fprintf(result_file, "\n\nEncoded Data:\n");
//     fwrite(encoded_data, 1, file_size, result_file);
//     fprintf(result_file, "\n\nDecoded Data:\n");
//     fwrite(decoded_data, 1, file_size, result_file);

//     // Write MD5 checksums
//     fprintf(result_file, "\n\nOriginal MD5: ");
//     for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
//         fprintf(result_file, "%02x", original_md5[i]);
//     }

//     fprintf(result_file, "\nDecoded MD5: ");
//     for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
//         fprintf(result_file, "%02x", decoded_md5[i]);
//     }

//     // Write the comparison result
//     if (memcmp(original_md5, decoded_md5, MD5_DIGEST_LENGTH) == 0) {
//         fprintf(result_file, "\n\nMD5 check passed: Decoded data matches original input.\n");
//     } else {
//         fprintf(result_file, "\n\nMD5 check failed: Decoded data does not match original input.\n");
//     }

//     // Clean up
//     fclose(result_file);
//     free(input_data);
//     free(encoded_data);
//     free(decoded_data);

//     return 0;
// }
// ```

// This code provides a complete implementation of the MD5 algorithm. The `MD5Init`, `MD5Update`, and `MD5Final` functions are used to initialize the context, process input data, and finalize the hash computation, respectively. The `MD5Transform` function performs the core MD5 transformation processing using bitwise operations and predefined constants.

// Don't forget to include the `md5.h` file in your source files where you want to use these functions.

// To compile the code, you may use a command like:

// ```sh
// gcc -o md5 main.c md5.c
// ```

// Make sure `md5.h` is in the same directory as your source files or in an include path.