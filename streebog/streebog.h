#ifndef __STREEBOG_H_
#define __STREEBOG_H_

#include <stdint.h>
#include <stddef.h>

#define BLOCK_SIZE 8

// message block of 512 bits
typedef uint64_t block_t[BLOCK_SIZE];

struct streebog_context {
        uint64_t h[BLOCK_SIZE]; // current hash value
        uint64_t N[BLOCK_SIZE]; 
        uint64_t EPSILON[BLOCK_SIZE];
};

// init streebog-512 context pointed by ctx
void
init_512_context(struct streebog_context *ctx);

// init streebog-256 context pointed by ctx
void
init_256_context(struct streebog_context *ctx);

// process a single block of length block_len
// bytes should be in reverse order
void
process_block(struct streebog_context *ctx, block_t block, unsigned block_len);

// calculate the final result after all of the blocks have been processed
void
calculate_result(struct streebog_context *ctx);

// write 64 bytes of streebog-512 hash to result
void
get_512_result(struct streebog_context *ctx, uint8_t *result);

// write 32 bytes of streebog-256 hash to result
void
get_256_result(struct streebog_context *ctx, uint8_t *result);

// process vector vec of length len
// if the is_final flag is set to zero, then the last block isn't padded and
// the len must be divisible by 64
// otherwise, the last block is padded
void
process_vector(struct streebog_context *ctx, const uint8_t *vec, size_t len, int is_final);

// process string pointed by str
// the last block is always padded
void
process_string(struct streebog_context *ctx, const char *str);

#endif
