/* script used to generate streebog-precalc.h */
#include "streebog-initial.h"

#include <stdint.h>
#include <stdio.h>

/* result[offset][byte] is the result of the linear transform applied to byte
 * located on offset
 */
uint64_t result[8][256];

#define BYTE_SIZE 8

void generate_result() {
        for (int offset = 0; offset < 8; ++offset) {
                for (int byte = 0; byte < 256; ++byte) {
                        result[offset][byte] = 0;
                        for (int bit = 0; bit < 8; ++bit) {
                                result[offset][byte] ^= ((byte >> bit) & 1) *
                                        l_matrix[63 - (bit + offset * BYTE_SIZE)];
                        }
                }
        }
}

#define ITEMS_PER_LINE 4

void print_result() {
        printf("#include \"streebog.h\"\n\n");
        printf("/* result[offset][byte] is the result of the linear"
               "transform applied to byte\n"
               " * located on offset\n"
               " */\n");
        printf("uint64_t precalc_matrix[%d][%d] = {\n", 8, 256);
        for (int offset = 0; offset < 8; ++offset) {
                printf("        /* %d */ {", offset);
                for (int byte = 0; byte < 256; ++byte) {
                        if (byte % ITEMS_PER_LINE == 0) {
                                printf("\n        ");
                        }
                        printf("0x%016lx", result[offset][byte]);
                        if (byte + 1 < 256) {
                                printf(", ");
                        }
                }
                printf("}");
                if (offset < 8) {
                        printf(",");
                }
                printf("\n");
        }
        printf("};\n");
}

int main() {
        generate_result();
        print_result();
}
