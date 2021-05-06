#include <linux/types.h>
#include <byteswap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// initial values

__u8 pi_bijection[256] = {
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4,
        77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205,
        95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1,
        142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212,
        211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253,
        58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
        183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111,
        157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
        128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121,
        214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220,
        232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184,
        56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
        165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55,
        107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141,
        83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203,
        155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192,
        209, 102, 175, 194, 57, 75, 99, 182
};

__u8 tau_bijection[64] = {
        0,  8, 16, 24, 32, 40, 48, 56,
        1,  9, 17, 25, 33, 41, 49, 57,
        2, 10, 18, 26, 34, 42, 50, 58,
        3, 11, 19, 27, 35, 43, 51, 59,
        4, 12, 20, 28, 36, 44, 52, 60,
        5, 13, 21, 29, 37, 45, 53, 61,
        6, 14, 22, 30, 38, 46, 54, 62,
        7, 15, 23, 31, 39, 47, 55, 63
};


// matrix used in linear transform stage
__u64 l_matrix[64] = {
        0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
        0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
        0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
        0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
        0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
        0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
        0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
        0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
        0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
        0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
        0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
        0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
        0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
        0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
        0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
        0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083
};

// iterational constants, most significant bit first
__u64 c_iterational[12][8] = {
        {0xb1085bda1ecadae9, 0xebcb2f81c0657c1f, 0x2f6a76432e45d016, 0x714eb88d7585c4fc,
         0x4b7ce09192676901, 0xa2422a08a460d315, 0x05767436cc744d23, 0xdd806559f2a64507},
        {0x6fa3b58aa99d2f1a, 0x4fe39d460f70b5d7, 0xf3feea720a232b98, 0x61d55e0f16b50131,
         0x9ab5176b12d69958, 0x5cb561c2db0aa7ca, 0x55dda21bd7cbcd56, 0xe679047021b19bb7},
        {0xf574dcac2bce2fc7, 0x0a39fc286a3d8435, 0x06f15e5f529c1f8b, 0xf2ea7514b1297b7b,
         0xd3e20fe490359eb1, 0xc1c93a376062db09, 0xc2b6f443867adb31, 0x991e96f50aba0ab2},
        {0xef1fdfb3e81566d2, 0xf948e1a05d71e4dd, 0x488e857e335c3c7d, 0x9d721cad685e353f,
         0xa9d72c82ed03d675, 0xd8b71333935203be, 0x3453eaa193e837f1, 0x220cbebc84e3d12e},
        {0x4bea6bacad474799, 0x9a3f410c6ca92363, 0x7f151c1f1686104a, 0x359e35d7800fffbd,
         0xbfcd1747253af5a3, 0xdfff00b723271a16, 0x7a56a27ea9ea63f5, 0x601758fd7c6cfe57},
        {0xae4faeae1d3ad3d9, 0x6fa4c33b7a3039c0, 0x2d66c4f95142a46c, 0x187f9ab49af08ec6,
         0xcffaa6b71c9ab7b4, 0x0af21f66c2bec6b6, 0xbf71c57236904f35, 0xfa68407a46647d6e},
        {0xf4c70e16eeaac5ec, 0x51ac86febf240954, 0x399ec6c7e6bf87c9, 0xd3473e33197a93c9,
         0x0992abc52d822c37, 0x06476983284a0504, 0x3517454ca23c4af3, 0x8886564d3a14d493},
        {0x9b1f5b424d93c9a7, 0x03e7aa020c6e4141, 0x4eb7f8719c36de1e, 0x89b4443b4ddbc49a,
         0xf4892bcb929b0690, 0x69d18d2bd1a5c42f, 0x36acc2355951a8d9, 0xa47f0dd4bf02e71e},
        {0x378f5a541631229b, 0x944c9ad8ec165fde, 0x3a7d3a1b25894224, 0x3cd955b7e00d0984,
         0x800a440bdbb2ceb1, 0x7b2b8a9aa6079c54, 0x0e38dc92cb1f2a60, 0x7261445183235adb},
        {0xabbedea680056f52, 0x382ae548b2e4f3f3, 0x8941e71cff8a78db, 0x1fffe18a1b336103,
         0x9fe76702af69334b, 0x7a1e6c303b7652f4, 0x3698fad1153bb6c3, 0x74b4c7fb98459ced},
        {0x7bcd9ed0efc889fb, 0x3002c6cd635afe94, 0xd8fa6bbbebab0761, 0x2001802114846679,
         0x8a1d71efea48b9ca, 0xefbacd1d7d476e98, 0xdea2594ac06fd85d, 0x6bcaa4cd81f32d1b},
        {0x378ee767f11631ba, 0xd21380b00449b17a, 0xcda43c32bcdf1d77, 0xf82012d430219f9b,
         0x5d80ef9d1891cc86, 0xe71da4aa88e12852, 0xfaf417d5d9b21b99, 0x48bc924af11bd720}
};

#define BLOCK_SIZE 8
#define BYTE_SIZE 8

typedef __u64 block_t[BLOCK_SIZE];

__u64
rorl_u64(__u64 n, int k)
{
        if (k == 0) {
                return n;
        }
        return (n << k) + (n >> (64 - k));
}

__u64
rorr_u64(__u64 n, int k)
{
        if (k == 0) {
                return n;
        }
        return (n >> k) + (n << (64 - k));
}

void
fill_with(block_t block, __u64 value)
{
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                block[i] = value;
        }
}

void
ring_add(block_t dest, block_t src)
{
        __u64 leftover = 0;
        for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
                __u64 old_value = dest[i];
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
                for (int byte_i = 0; byte_i < 8; ++byte_i) {
                        __u64 temp = rorr_u64(block[i], byte_i * BYTE_SIZE);
                        __u8 byte = temp & 255u;
                        temp = temp - byte + pi_bijection[byte];
                        block[i] = rorl_u64(temp, byte_i * BYTE_SIZE);
                }
        }
}

void
replace_byte(block_t block, int byte_i, __u8 byte)
{
        int i = byte_i >> 3; // div 8
        int internal_byte_i = byte_i & 7; // mod 8
        __u64 temp = rorr_u64(block[i], internal_byte_i * BYTE_SIZE);
        temp = ((temp >> BYTE_SIZE) << BYTE_SIZE) + byte;
        block[i] = rorl_u64(temp, internal_byte_i * BYTE_SIZE);
}

void
transform_permute(block_t block)
{
        __u64 result[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                for (int byte_i = i * 8; byte_i < (i + 1) * 8; ++byte_i) {
                        __u8 new_byte_i = tau_bijection[byte_i];
                        __u8 byte = (block[i] >> (byte_i * BYTE_SIZE)) & 255u;
                        replace_byte(result, BLOCK_SIZE * 8 - new_byte_i - 1, byte);
                }
        }
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                block[i] = result[i];
        }
}

__u64
transform_one_linear(__u64 n)
{
        __u64 res = 0;
        for (int i = 0; i < 64; ++i) {
                res ^= ((n >> (64 - i - 1)) & 1) * l_matrix[i];
        }
        return res;
}

void
transform_linear(block_t block)
{
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                block[i] = transform_one_linear(block[i]);
        }
}

void
transform_lps(block_t block)
{
        transform_substitute(block);
        transform_permute(block);
        transform_linear(block);
}

void
copy_block(block_t dest, block_t src)
{
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                dest[i] = src[i];
        }
}

#define K_BLOCK_COUNT 13

void
calculate_K_blocks(block_t *k_blocks)
{
        __u64 tmp_block[BLOCK_SIZE];
        copy_block(tmp_block, k_blocks[0]);
        for (int i = 1; i < K_BLOCK_COUNT; ++i) {
                // k_blocks[i - 1] is stored in tmp_block
                transform_xor(tmp_block, c_iterational[i - 1]);
                transform_lps(tmp_block);
                copy_block(k_blocks[i], tmp_block);
        }
}

void
calculate_E(block_t result, block_t K, block_t m)
{
        __u64 k_blocks[K_BLOCK_COUNT][BLOCK_SIZE];
        copy_block(k_blocks[0], K);
        calculate_K_blocks(k_blocks);
        copy_block(result, m);
        for (int i = 0; i < K_BLOCK_COUNT; ++i) {
                transform_xor(result, k_blocks[i]);
                if (i != K_BLOCK_COUNT - 1) {
                        transform_lps(result);
                }
        }
}

struct stribog_calculator {
        __u64 h[BLOCK_SIZE];
        __u64 N[BLOCK_SIZE];
        __u64 EPSILON[BLOCK_SIZE];
};

void
init_512_calculator(struct stribog_calculator *calc)
{
        fill_with(calc->h, 0);
        fill_with(calc->N, 0);
        for (int i = 0; i < BLOCK_SIZE; ++i) {
                calc->h[i] = 0;
                calc->N[i] = 0;
                calc->EPSILON[i] = 0;
        }
}

void
init_256_calculator(struct stribog_calculator *calc)
{
        fill_with(calc->h, 0x0101010101010101ull);
        fill_with(calc->N, 0);
        fill_with(calc->EPSILON, 0);
}

void
transform_g(struct stribog_calculator *calc, block_t block)
{
        __u64 tmp_block[BLOCK_SIZE];
        copy_block(tmp_block, calc->h);
        transform_xor(tmp_block, calc->N);
        transform_lps(tmp_block);
        calculate_E(tmp_block, tmp_block, block);
        transform_xor(tmp_block, calc->h);
        transform_xor(tmp_block, block);
        copy_block(calc->h, tmp_block);
}

void
process_block(struct stribog_calculator *calc, block_t block, unsigned block_len) 
{
       transform_g(calc, block); 
       __u64 tmp_block[BLOCK_SIZE];
       for (int i = 0; i < BLOCK_SIZE; ++i) {
                tmp_block[i] = 0;
       }
       tmp_block[BLOCK_SIZE - 1] = block_len;
       ring_add(calc->N, tmp_block);
       ring_add(calc->EPSILON, block);
}

void
calculate_result(struct stribog_calculator *calc)
{
        __u64 tmp_block[BLOCK_SIZE];
        copy_block(tmp_block, calc->N);
        fill_with(calc->N, 0);
        transform_g(calc, tmp_block);
        transform_g(calc, calc->EPSILON);
}

void
get_512_result(struct stribog_calculator *calc, __u8 *result)
{
        __u64 *result_u64 = (__u64*) result;
        for (int i = 0; i < 8; ++i) {
                result_u64[i] = calc->h[7 - i];
        }
}

void
get_256_result(struct stribog_calculator *calc, __u8 *result)
{
        __u64 *result_u64 = (__u64*) result;
        for (int i = 0; i < 4; ++i) {
                result_u64[i] = calc->h[3 - i];
        }
}

void
process_vector(struct stribog_calculator *calc, __u8 *vec, size_t len)
{
        __u64 block[BLOCK_SIZE];
        __u64 *block_ptr = (__u64*) (vec + len);
        int block_len = BLOCK_SIZE * 8 * BYTE_SIZE;
        while (len >= block_len / BYTE_SIZE) {
                block_ptr -= BLOCK_SIZE;
                // reversed order
                for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
                        block[i] = *(block_ptr++);
                }
                process_block(calc, block, block_len);
                block_ptr -= BLOCK_SIZE;
                len -= block_len / BYTE_SIZE;
        }
        // apply padding
        fill_with(block, 0);
        int bit_len = len * BYTE_SIZE;
        unsigned zero_count = block_len - 1 - bit_len; 
        __u8 bits[block_len];
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
        process_block(calc, block, bit_len);
}

void
process_string(struct stribog_calculator *calc, char *str)
{
        process_vector(calc, str, strlen(str));
}

int
main()
{
        char msg[64];
        strcpy(msg, "012345678901234567890123456789012345678901234567890123456789012");
        struct stribog_calculator calc;
        init_256_calculator(&calc);
        process_string(&calc, msg);
        calculate_result(&calc);
        __u8 result[32];
        get_256_result(&calc, result);
        for (int i = 0; i < 32; ++i) {
                printf("%02x", result[i]);       
        }
        printf("\n");
}
