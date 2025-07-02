#include "shared.h"
#include <omp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CH(e, f, g) ((e & f) ^ ((~e) & g)) // choose f if e = 0 and g if e = 1

void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3])
{
    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
    z[2] = x[2] ^ y[2];
}

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View views[3],
             int *countY)
{
    uint32_t r[3] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount),
                     getRandom32(randomness[2], *randCount)};
    *randCount += 4; // Because 32 bits = 4 octets
    uint32_t t[3] = {0};

    t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
    t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
    t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
    z[0] = t[0];
    z[1] = t[1];
    z[2] = t[2];
    views[0].y[*countY] = z[0];
    views[1].y[*countY] = z[1];
    views[2].y[*countY] = z[2];
    (*countY)++;
}

void mpc_NEGATE(uint32_t x[3], uint32_t z[3])
{
    z[0] = ~x[0];
    z[1] = ~x[1];
    z[2] = ~x[2];
}

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View views[3],
             int *countY)
{
    uint32_t c[3] = {0};
    uint32_t r[3] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount),
                     getRandom32(randomness[2], *randCount)};
    *randCount += 4;
    uint8_t a[3], b[3];

    uint8_t t;

    for (int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ c[0], i);
        a[1] = GETBIT(x[1] ^ c[1], i);
        a[2] = GETBIT(x[2] ^ c[2], i);

        b[0] = GETBIT(y[0] ^ c[0], i);
        b[1] = GETBIT(y[1] ^ c[1], i);
        b[2] = GETBIT(y[2] ^ c[2], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
        SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

        t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
        SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

        t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
        SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
    }

    z[0] = x[0] ^ y[0] ^ c[0];
    z[1] = x[1] ^ y[1] ^ c[1];
    z[2] = x[2] ^ y[2] ^ c[2];

    views[0].y[*countY] = c[0];
    views[1].y[*countY] = c[1];
    views[2].y[*countY] = c[2];
    *countY += 1;
}

void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int *randCount, View views[3],
              int *countY)
{
    uint32_t c[3] = {0};
    uint32_t r[3] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount),
                     getRandom32(randomness[2], *randCount)};
    *randCount += 4;

    uint8_t a[3], b[3];

    uint8_t t;

    for (int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ c[0], i);
        a[1] = GETBIT(x[1] ^ c[1], i);
        a[2] = GETBIT(x[2] ^ c[2], i);

        b[0] = GETBIT(y ^ c[0], i);
        b[1] = GETBIT(y ^ c[1], i);
        b[2] = GETBIT(y ^ c[2], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
        SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

        t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
        SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

        t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
        SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
    }

    z[0] = x[0] ^ y ^ c[0];
    z[1] = x[1] ^ y ^ c[1];
    z[2] = x[2] ^ y ^ c[2];

    views[0].y[*countY] = c[0];
    views[1].y[*countY] = c[1];
    views[2].y[*countY] = c[2];
    *countY += 1;
}

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[])
{
    z[0] = RIGHTROTATE(x[0], i);
    z[1] = RIGHTROTATE(x[1], i);
    z[2] = RIGHTROTATE(x[2], i);
}

void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3])
{
    z[0] = x[0] >> i;
    z[1] = x[1] >> i;
    z[2] = x[2] >> i;
} // shift means leaving zeros on the left

void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
             View views[3], int *countY)
{
    uint32_t t0[3];
    uint32_t t1[3];

    mpc_XOR(a, b, t0);
    mpc_XOR(a, c, t1);
    mpc_AND(t0, t1, z, randomness, randCount, views, countY);
    mpc_XOR(z, a, z);
} // maj means choosing 0 if 0 is in majority beyound 3 bits (same goes for 1)

void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
            View views[3], int *countY)
{
    uint32_t t0[3];

    // e & (f^g) ^ g
    mpc_XOR(f, g, t0);
    mpc_AND(e, t0, t0, randomness, randCount, views, countY);
    mpc_XOR(t0, g, z);
}

void mpc_sha256(unsigned char *inputs[3], int numBits, unsigned char *randomness[3], char *results[3], View views[3],
                int *countY, int *randCount)
{

    int chars = numBits >> 3; // Dividing by 8 = getting Bytes number
    unsigned char *chunks[3];
    uint32_t w[64][3];

    for (int i = 0; i < 3; i++)
    {
        chunks[i] = calloc(64, 1); // 512 bits
        memcpy(chunks[i], inputs[i], chars);
        chunks[i][chars] = 0x80;
        chunks[i][62] = numBits >> 8;
        chunks[i][63] = numBits;

        for (int j = 0; j < 16; j++)
        {
            w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16) | (chunks[i][j * 4 + 2] << 8) |
                      chunks[i][j * 4 + 3];
        }
        free(chunks[i]);
    }

    uint32_t s0[3], s1[3];
    uint32_t t0[3], t1[3];

    for (int j = 16; j < 64; j++)
    {
        mpc_RIGHTROTATE(w[j - 15], 7, t0);
        mpc_RIGHTROTATE(w[j - 15], 18, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTSHIFT(w[j - 15], 3, t1);
        mpc_XOR(t0, t1, s0);
        mpc_RIGHTROTATE(w[j - 2], 17, t0);
        mpc_RIGHTROTATE(w[j - 2], 19, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTSHIFT(w[j - 2], 10, t1);
        mpc_XOR(t0, t1, s1);
        mpc_ADD(w[j - 16], s0, t1, randomness, randCount, views, countY);
        mpc_ADD(w[j - 7], t1, t1, randomness, randCount, views, countY);
        mpc_ADD(t1, s1, w[j], randomness, randCount, views, countY);
    }

    uint32_t a[3] = {hA[0], hA[0], hA[0]};
    uint32_t b[3] = {hA[1], hA[1], hA[1]};
    uint32_t c[3] = {hA[2], hA[2], hA[2]};
    uint32_t d[3] = {hA[3], hA[3], hA[3]};
    uint32_t e[3] = {hA[4], hA[4], hA[4]};
    uint32_t f[3] = {hA[5], hA[5], hA[5]};
    uint32_t g[3] = {hA[6], hA[6], hA[6]};
    uint32_t h[3] = {hA[7], hA[7], hA[7]};
    uint32_t temp1[3], temp2[3], maj[3];

    for (int i = 0; i < 64; i++)
    {
        mpc_RIGHTROTATE(e, 6, t0);
        mpc_RIGHTROTATE(e, 11, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTROTATE(e, 25, t1);
        mpc_XOR(t0, t1, s1);
        mpc_ADD(h, s1, t0, randomness, randCount, views, countY);
        mpc_CH(e, f, g, t1, randomness, randCount, views, countY);
        mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);
        mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);
        mpc_ADD(t1, w[i], temp1, randomness, randCount, views, countY);
        mpc_RIGHTROTATE(a, 2, t0);
        mpc_RIGHTROTATE(a, 13, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTROTATE(a, 22, t1);
        mpc_XOR(t0, t1, s0);
        mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);
        mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);
        memcpy(h, g, sizeof(uint32_t) * 3);
        memcpy(g, f, sizeof(uint32_t) * 3);
        memcpy(f, e, sizeof(uint32_t) * 3);
        mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
        memcpy(d, c, sizeof(uint32_t) * 3);
        memcpy(c, b, sizeof(uint32_t) * 3);
        memcpy(b, a, sizeof(uint32_t) * 3);
        mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
    }

    uint32_t hHa[8][3] = {{hA[0], hA[0], hA[0]}, {hA[1], hA[1], hA[1]}, {hA[2], hA[2], hA[2]}, {hA[3], hA[3], hA[3]},
                          {hA[4], hA[4], hA[4]}, {hA[5], hA[5], hA[5]}, {hA[6], hA[6], hA[6]}, {hA[7], hA[7], hA[7]}};
    mpc_ADD(hHa[0], a, hHa[0], randomness, randCount, views, countY);
    mpc_ADD(hHa[1], b, hHa[1], randomness, randCount, views, countY);
    mpc_ADD(hHa[2], c, hHa[2], randomness, randCount, views, countY);
    mpc_ADD(hHa[3], d, hHa[3], randomness, randCount, views, countY);
    mpc_ADD(hHa[4], e, hHa[4], randomness, randCount, views, countY);
    mpc_ADD(hHa[5], f, hHa[5], randomness, randCount, views, countY);
    mpc_ADD(hHa[6], g, hHa[6], randomness, randCount, views, countY);
    mpc_ADD(hHa[7], h, hHa[7], randomness, randCount, views, countY);

    for (int i = 0; i < 8; i++)
    {
        mpc_RIGHTSHIFT(hHa[i], 24, t0);
        results[0][i * 4] = t0[0];
        results[1][i * 4] = t0[1];
        results[2][i * 4] = t0[2];
        mpc_RIGHTSHIFT(hHa[i], 16, t0);
        results[0][i * 4 + 1] = t0[0];
        results[1][i * 4 + 1] = t0[1];
        results[2][i * 4 + 1] = t0[2];
        mpc_RIGHTSHIFT(hHa[i], 8, t0);
        results[0][i * 4 + 2] = t0[0];
        results[1][i * 4 + 2] = t0[1];
        results[2][i * 4 + 2] = t0[2];

        results[0][i * 4 + 3] = hHa[i][0];
        results[1][i * 4 + 3] = hHa[i][1];
        results[2][i * 4 + 3] = hHa[i][2];
    }

    for (int i = 0; i < 8; i++)
    {
        views[0].y[*countY] = (results[0][i * 4] << 24) | (results[0][i * 4 + 1] << 16) | (results[0][i * 4 + 2] << 8) |
                              results[0][i * 4 + 3];
        views[1].y[*countY] = (results[1][i * 4] << 24) | (results[1][i * 4 + 1] << 16) | (results[1][i * 4 + 2] << 8) |
                              results[1][i * 4 + 3];
        views[2].y[*countY] = (results[2][i * 4] << 24) | (results[2][i * 4 + 1] << 16) | (results[2][i * 4 + 2] << 8) |
                              results[2][i * 4 + 3];
        *countY += 1;
    }
}

a building_views(unsigned char digest[32], unsigned char shares[3][INPUT_LEN], unsigned char *randomness[3],
                 View views[3], unsigned char public_key[8192])
{
    // Declaring the output a
    a a;
    int index_in_a = 0;
    int index_in_pub_key = 0;

    // First grab the share of (digest||commitment_key)
    unsigned char *inputs[3];
    for (int i = 0; i < 3; i++)
    {
        inputs[i] = calloc(55, 1);
        memcpy(inputs[i] + 32, shares[i], 23);
    }
    memcpy(inputs[0], digest, 32); // digest isn't secret so don´t need to be shared

    int *countY = calloc(1, sizeof(int));
    int *randCount = calloc(1, sizeof(int));
    unsigned char *results[3];
    results[0] = malloc(32);
    results[1] = malloc(32);
    results[2] = malloc(32);

    // Computing sha256(digest||commit-key)
    mpc_sha256(inputs, 55 * 8, randomness, results, views, countY, randCount);

    // xoring with secret commitment
    uint32_t t0[3], t1[3], tmp[3];

    for (int i = 0; i < 8; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            memcpy(&t0[j], shares[j] + 23 + 4 * i, 4);
            memcpy(&t1[j], results[j] + 4 * i, 4);
        }

        mpc_XOR(t0, t1, tmp);

        for (int j = 0; j < 3; j++)
        {
            views[j].y[*countY] = tmp[j];
            memcpy(&a.yp[j][index_in_a], &tmp[j], 4);
        }
        index_in_a++;
        (*countY)++;
    }

    // Verifying signature
    for (int j = 0; j < 3; j++)
    {
        free(inputs[j]);
        inputs[j] = malloc(32);
    }

    for (int i = 0; i < 256; i++)
    {
        int index_in_input = 55 + 32 * i;
        index_in_pub_key = 32 * i;

        // Computing SHA256 of WOTS_signature[i]
        for (int j = 0; j < 3; j++)
        {
            memcpy(inputs[j], shares[j] + index_in_input, 32);
        }

        mpc_sha256(inputs, SHA256_DIGEST_LENGTH * 8, randomness, results, views, countY, randCount);

        // Xoring the result with WOTS_signature[i]
        uint32_t verif_result[3][8];

        printf("\n %d: ", i);
        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], shares[k] + index_in_input + 4 * j, 4);
                memcpy(&t1[k], results[k] + 4 * j, 4);
            }

            // if (i == 255 && j == 0)
            // {
            //     uint32_t xor_t0 = t0[0] ^ t0[1] ^ t0[2];
            //     uint32_t xor_t1 = t1[0] ^ t1[1] ^ t1[2];
            //     printf("XOR des trois t0: %08x\n", xor_t0);
            //     printf("XOR des trois t1: %08x\n", xor_t1);
            // }

            mpc_XOR(t0, t1, tmp);

            for (int k = 0; k < 3; k++)
            {
                verif_result[k][j] = tmp[k];
            }

            // uint32_t xor_tmp = tmp[0] ^ tmp[1] ^ tmp[2];
            // printf("%08x", xor_tmp);
        }

        // Building MASK: getting a share of i-th bit of the shared commitment and extending it in 32bits word
        uint32_t mask[3];
        int byte = i >> 3;
        int bit = i & 7;

        for (int j = 0; j < 3; j++)
        {
            uint8_t v = shares[j][23 + byte];
            uint32_t b = (v >> bit) & 1;
            mask[j] = 0u - b;
            views[j].y[*countY] = mask[j];
        }
        *(countY) += 1;

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &verif_result[k][j], 4);
            }

            mpc_AND(t0, mask, tmp, randomness, randCount, views, countY);

            for (int k = 0; k < 3; k++)
            {
                verif_result[k][j] = tmp[k];
            }
        }

        // Xoring with sha256 of WOTS_signature[i]
        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &verif_result[k][j], 4);
                memcpy(&t1[k], results[k] + 4 * j, 4);
            }

            mpc_XOR(t0, t1, tmp);

            for (int k = 0; k < 3; k++)
            {
                views[k].y[*countY] = tmp[k];
                verif_result[k][j] = tmp[k];
            }
            (*countY)++;
        }

        // Xoring with public_key[i]
        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &verif_result[k][j], 4);
            }
            memset(t1, 0, sizeof(t1));
            memcpy(&t1[0], public_key + index_in_pub_key + 4 * j, 4);

            mpc_XOR(t0, t1, tmp);

            for (int k = 0; k < 3; k++)
            {
                views[k].y[*countY] = tmp[k];
            }
            (*countY)++;

            for (int k = 0; k < 3; k++)
            {
                memcpy(&a.yp[k][index_in_a], &tmp[k], 4);
            }
            // printf("%08x", a.yp[0][index_in_a] ^ a.yp[1][index_in_a] ^ a.yp[2][index_in_a]);
            index_in_a++;
        }
    }

    for (int i = 0; i < 3; i++)
    {
        free(inputs[i]);
        free(results[i]);
    }

    // for (int i = 0; i < 257 * 8; i++)
    // {
    //     printf("%08x", a.yp[0][i] ^ a.yp[1][i] ^ a.yp[2][i]);
    //     if (i % 8 == 7)
    //     {
    //         printf("\n");
    //     }
    // }

    free(randCount);
    free(countY);

    return a;
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3])
{
    z z;
    memcpy(z.ke, keys[e], 16);
    memcpy(z.ke1, keys[(e + 1) % 3], 16);
    z.ve = views[e];
    z.ve1 = views[(e + 1) % 3];
    memcpy(z.re, rs[e], 4);
    memcpy(z.re1, rs[(e + 1) % 3], 4);

    return z;
}

int main(void)
{
    setbuf(stdout, NULL);
    srand((unsigned)time(NULL));
    init_EVP();
    openmp_thread_setup(); // OpenMP = Multi Threading

    unsigned char garbage[4];
    if (RAND_bytes(garbage, 4) != 1)
    {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
    }

    // Getting m
    char *message = NULL;
    size_t bufferSize = 0;
    printf("\nPlease enter your message:\n");
    getline(&message, &bufferSize, stdin);
    message[strlen(message) - 1] = '\0'; // to remove '\n' at the end

    // Computing message digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), digest);
    free(message);

    // Getting commitment key
    char hexInput[2 * COMMIT_KEY_LEN + 2];
    unsigned char commitment_key[COMMIT_KEY_LEN];

    printf("\nEnter your commitment key (46 hex chars):\n");
    fgets(hexInput, sizeof(hexInput), stdin);

    for (int i = 0; i < COMMIT_KEY_LEN; i++)
    {
        unsigned int byte;
        sscanf(&hexInput[i * 2], "%2x", &byte);
        commitment_key[i] = (unsigned char)byte;
    }

    // Getting commitment
    char hexInput2[2 * COMMIT_LEN + 2];
    unsigned char commitment[COMMIT_LEN];

    printf("\nEnter your commitment (64 hex chars):\n");
    fgets(hexInput2, sizeof(hexInput2), stdin);

    for (int i = 0; i < COMMIT_LEN; i++)
    {
        unsigned int byte;
        sscanf(&hexInput2[i * 2], "%2x", &byte);
        commitment[i] = (unsigned char)byte;
    }

    // Getting WOTS signature
    int c1;
    int c2;
    FILE *fp = fopen("signature.txt", "r");
    unsigned char sigma[8192];
    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 32; j++)
        {
            c1 = fgetc(fp);
            while (c1 == '\n')
            {
                c1 = fgetc(fp);
            }

            c2 = fgetc(fp);
            while (c2 == '\n')
            {
                c2 = fgetc(fp);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            sigma[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    fclose(fp);

    // Building input
    unsigned char input[INPUT_LEN];
    memcpy(input, commitment_key, 23);
    memcpy(input + 23, commitment, 32);
    memcpy(input + 55, sigma, 8192);

    // Generating keys
    unsigned char keys[NUM_ROUNDS][3][16];

    if (RAND_bytes(keys, NUM_ROUNDS * 3 * 16) != 1)
    {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
    }

    // Getting public_key
    fp = fopen("public_key.txt", "r");
    unsigned char public_key[8192];
    for (int i = 0; i < 256; ++i)
        for (int j = 0; j < 32; ++j)
        {
            c1 = fgetc(fp);
            while (c1 == '\n')
            {
                c1 = fgetc(fp);
            }

            c2 = fgetc(fp);
            while (c2 == '\n')
            {
                c2 = fgetc(fp);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            public_key[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    fclose(fp);

    // Sharing secrets
    unsigned char shares[NUM_ROUNDS][3][INPUT_LEN];
    if (RAND_bytes(shares, NUM_ROUNDS * 3 * INPUT_LEN) != 1)
    {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
    }

    View localViews[NUM_ROUNDS][3];

#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < INPUT_LEN; j++)
        {
            shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
        }
        for (int j = 0; j < 3; j++)
        {
            memcpy(localViews[k][j].x, shares[k][j], INPUT_LEN);
        }
    }

    // Generating randomness
    unsigned char *randomness[NUM_ROUNDS][3];
#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 3; j++)
        {
            randomness[k][j] = malloc(Random_Bytes_Needed * sizeof(unsigned char));
            getAllRandomness(keys[k][j], randomness[k][j], Random_Bytes_Needed);
            localViews[k][j].y = malloc(ySize * sizeof(uint32_t));
        }
    }

    /* ============================================== Running Circuit ============================================== */

    a as[NUM_ROUNDS];
#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        as[k] = building_views(digest, shares[k], randomness[k], localViews[k], public_key);
        for (int j = 0; j < 3; j++)
        {
            free(randomness[k][j]);
        }
    }

    /* =============================================================================================================
     */

    // Committing the views
    unsigned char rs[NUM_ROUNDS][3][4]; // Commit keys
    if (RAND_bytes(rs, NUM_ROUNDS * 3 * 4) != 1)
    {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
    }

#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        H(keys[k][0], localViews[k][0], rs[k][0], &hash1);
        memcpy(as[k].h[0], &hash1, 32);
        H(keys[k][1], localViews[k][1], rs[k][1], &hash1);
        memcpy(as[k].h[1], &hash1, 32);
        H(keys[k][2], localViews[k][2], rs[k][2], &hash1);
        memcpy(as[k].h[2], &hash1, 32);
    }

    // Generating E
    int es[NUM_ROUNDS];
    H3(digest, as, NUM_ROUNDS, es);

    // Packing Z
    z *zs = malloc(sizeof(z) * NUM_ROUNDS);

#pragma omp parallel for
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        zs[i] = prove(es[i], keys[i], rs[i], localViews[i]);
    }

    // Writing to file
    FILE *file = fopen("proof.bin", "wb");

    fwrite(as, sizeof(a), NUM_ROUNDS, file);

    for (int i = 0; i < NUM_ROUNDS; ++i)
    {
        fwrite(&zs[i], sizeof(z), 1, file);

        fwrite(zs[i].ve.y, sizeof(uint32_t), ySize, file);
        fwrite(zs[i].ve1.y, sizeof(uint32_t), ySize, file);
    }

    fclose(file);
    free(zs);
    return EXIT_SUCCESS;
}