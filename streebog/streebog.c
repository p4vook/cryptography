#include "streebog.h"
#include "streebog-initial.h"
#include <byteswap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BYTE_SIZE 8

uint64_t
rorl_u64(uint64_t n, int k)
{
        return (n << k) ^ (n >> (64 - k));
}

uint64_t
rorr_u64(uint64_t n, int k)
{
        return (n >> k) ^ (n << (64 - k));
}

void
fill_with(block_t block, uint64_t value)
{
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                block[i] = value;
        }
}

void
copy_block(block_t dest, block_t src)
{
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                dest[i] = src[i];
        }
}

void
ring_add(block_t dest, block_t src)
{
        uint64_t leftover = 0;
        for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
                uint64_t old_value = dest[i];
                dest[i] += src[i] + leftover;
                if (dest[i] < old_value || (dest[i] == old_value && src[i] != 0)) {
                        leftover = 1;
                } else {
                        leftover = 0;
                }
        }
}

void
transform_xor(block_t block, block_t k)
{
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                block[i] ^= k[i];
        }
}

void
transform_substitute(block_t block)
{
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                for (int byte_i = 7; byte_i >= 0; --byte_i) {
                        uint8_t byte = block[i] & 0xFF;
                        block[i] = block[i] - byte + pi_bijection[byte];
                        block[i] = rorr_u64(block[i], BYTE_SIZE);
                }
        }
}

void
replace_byte(block_t block, int byte_i, uint8_t byte)
{
        int i = byte_i >> 3; // div 8
        int internal_byte_i = byte_i & 7; // mod 8
        uint64_t temp = rorr_u64(block[i], internal_byte_i * BYTE_SIZE);
        temp = ((temp >> BYTE_SIZE) << BYTE_SIZE) + byte;
        block[i] = rorl_u64(temp, internal_byte_i * BYTE_SIZE);
}

void
transform_true_permute(block_t block)
{
        uint64_t result[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                for (int byte_i = i * 8; byte_i < (i + 1) * 8; ++byte_i) {
                        uint8_t new_byte_i = tau_bijection[byte_i];
                        uint8_t byte = (block[i] >> (byte_i * BYTE_SIZE)) & 255u;
                        replace_byte(result, BLOCK_SIZE * 8 - new_byte_i - 1, byte);
                }
        }
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                block[i] = result[i];
        }
}

void
transform_permute(block_t block)
{
        uint64_t result[BLOCK_SIZE];
        fill_with(result, 0);
        for (int byte_i = 0; byte_i < 8; ++byte_i) {
                for (int i = 0; i < BLOCK_SIZE; ++i) {
                        result[7 - byte_i] ^= ((block[7 - i] >> (byte_i * BYTE_SIZE)) & 0xFF) << (i * BYTE_SIZE);
                }
        }
        copy_block(block, result);
}

void
transform_linear(block_t block)
{
        uint64_t res[BLOCK_SIZE];
        fill_with(res, 0);
        for (int bit = 0; bit < 64; ++bit) {
                for (int i = 0; i < BLOCK_SIZE; ++i) {
                        res[i] ^= ((block[i] >> (64 - bit - 1)) & 1) * l_matrix[bit];
                }
        }
        copy_block(block, res);
}

void
transform_lps(block_t block)
{
        transform_substitute(block);
        transform_permute(block);
        transform_linear(block);
}

#define K_BLOCK_COUNT 13

void
calculate_E(block_t result, block_t K, block_t m)
{
        uint64_t tmp_block[BLOCK_SIZE];
        copy_block(tmp_block, K);
        copy_block(result, m);
        for (int i = 0; i < K_BLOCK_COUNT - 1; ++i) {
                transform_xor(result, tmp_block);
                transform_lps(result);
                // calculate next K block
                transform_xor(tmp_block, c_iterational[i]);
                transform_lps(tmp_block);
        }
        transform_xor(result, tmp_block);
}

void
init_512_context(struct streebog_context *ctx)
{
        fill_with(ctx->h, 0);
        fill_with(ctx->N, 0);
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                ctx->h[i] = 0;
                ctx->N[i] = 0;
                ctx->EPSILON[i] = 0;
        }
}

void
init_256_context(struct streebog_context *ctx)
{
        fill_with(ctx->h, 0x0101010101010101ull);
        fill_with(ctx->N, 0);
        fill_with(ctx->EPSILON, 0);
}

void
transform_g(struct streebog_context *ctx, block_t block)
{
        uint64_t tmp_block[BLOCK_SIZE];
        copy_block(tmp_block, ctx->h);
        transform_xor(tmp_block, ctx->N);
        transform_lps(tmp_block);
        calculate_E(tmp_block, tmp_block, block);
        transform_xor(ctx->h, tmp_block);
        transform_xor(ctx->h, block);
}

void
process_block(struct streebog_context *ctx, block_t block, unsigned block_len) 
{
       transform_g(ctx, block); 
       uint64_t tmp_block[BLOCK_SIZE];
       for (int i = 0; i < BLOCK_SIZE; ++i) {
                tmp_block[i] = 0;
       }
       tmp_block[BLOCK_SIZE - 1] = block_len;
       ring_add(ctx->N, tmp_block);
       ring_add(ctx->EPSILON, block);
}

void
calculate_result(struct streebog_context *ctx)
{
        uint64_t tmp_block[BLOCK_SIZE];
        copy_block(tmp_block, ctx->N);
        fill_with(ctx->N, 0);
        transform_g(ctx, tmp_block);
        transform_g(ctx, ctx->EPSILON);
}

void
get_512_result(struct streebog_context *ctx, uint8_t *result)
{
        uint64_t *result_u64 = (uint64_t*) result;
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                result_u64[i] = ctx->h[BLOCK_SIZE - 1 - i];
        }
}

void
get_256_result(struct streebog_context *ctx, uint8_t *result)
{
        uint64_t *result_u64 = (uint64_t*) result;
        for (int i = 0; i < BLOCK_SIZE / 2; ++i) {
                result_u64[i] = ctx->h[BLOCK_SIZE / 2 - 1 - i];
        }
}

void
process_vector(struct streebog_context *ctx, const uint8_t *vec, size_t len, int is_final)
{
        uint64_t block[BLOCK_SIZE];
        const uint64_t *block_ptr = (const uint64_t*) vec;
        int block_len = BLOCK_SIZE * 8 * BYTE_SIZE;
        while (len >= block_len / BYTE_SIZE) {
                // reversed order
                for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
                        block[i] = *(block_ptr++);
                }
                process_block(ctx, block, block_len);
                len -= block_len / BYTE_SIZE;
                vec += block_len / BYTE_SIZE;
        }
        if (!is_final) {
                return;
        }
        // apply padding
        fill_with(block, 0);
        int bit_len = len * BYTE_SIZE;
        unsigned zero_count = block_len - 1 - bit_len; 
        uint8_t bits[block_len];
        int bit_i;
        for (bit_i = 0; bit_i < zero_count; ++bit_i) {
                bits[bit_i] = 0;
        }
        bits[bit_i++] = 1;
        // next bytes in reverse order
        bit_i = block_len;
        while (len > 0) {
                bit_i -= BYTE_SIZE;
                for (int char_bit_i = BYTE_SIZE - 1; char_bit_i >= 0; --char_bit_i) {
                        bits[bit_i++] = ((*vec) >> char_bit_i) & 1;
                }
                bit_i -= BYTE_SIZE;
                ++vec;
                --len;
        }
        for (int i = 0; i < block_len; ++i) {
                int div = i / 64;
                int mod = i % 64;
                if (bits[i]) {
                        block[div] |= (1ull << (63 - mod));
                }
        }
        process_block(ctx, block, bit_len);
}

void
process_string(struct streebog_context *ctx, const char *str)
{
        process_vector(ctx, (const uint8_t *) str, strlen(str), 1);
}

void
test()
{
        char msg[64];
        strcpy(msg, "012345678901234567890123456789012345678901234567890123456789012");
        struct streebog_context ctx;
        init_256_context(&ctx);
        process_string(&ctx, msg);
        calculate_result(&ctx);
        uint8_t result[32];
        get_256_result(&ctx, result);
        for (int i = 0; i < 32; ++i) {
                printf("%02x", result[i]);       
        }
        printf("\n");
}
