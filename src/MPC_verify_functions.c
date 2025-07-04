#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][2912],
                   int *randCount, int *countY)
{
    uint32_t r[2] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint32_t t = 0;

    t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
    if (ve.y[*countY] != t)
    {
        return 1;
    }
    z[0] = t;
    z[1] = ve1.y[*countY];

    (*countY)++;
    return 0;
}

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][2912],
                   int *randCount, int *countY)
{
    uint32_t r[2] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint8_t a[2], b[2];

    uint8_t t;

    for (int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ ve.y[*countY], i);
        a[1] = GETBIT(x[1] ^ ve1.y[*countY], i);

        b[0] = GETBIT(y[0] ^ ve.y[*countY], i);
        b[1] = GETBIT(y[1] ^ ve1.y[*countY], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
        if (GETBIT(ve.y[*countY], i + 1) != (t ^ (a[0] & b[0]) ^ GETBIT(ve.y[*countY], i) ^ GETBIT(r[0], i)))
        {
            return 1;
        }
    }

    z[0] = x[0] ^ y[0] ^ ve.y[*countY];
    z[1] = x[1] ^ y[1] ^ ve1.y[*countY];
    (*countY)++;
    return 0;
}

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[])
{
    z[0] = RIGHTROTATE(x[0], i);
    z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2])
{
    z[0] = x[0] >> i;
    z[1] = x[1] >> i;
}

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1,
                   unsigned char randomness[2][2912], int *randCount, int *countY)
{
    uint32_t t0[3];
    uint32_t t1[3];

    mpc_XOR2(a, b, t0);
    mpc_XOR2(a, c, t1);
    if (mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1)
    {
        return 1;
    }
    mpc_XOR2(z, a, z);
    return 0;
}

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1,
                  unsigned char randomness[2][2912], int *randCount, int *countY)
{

    uint32_t t0[3];
    mpc_XOR2(f, g, t0);
    if (mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1)
    {
        return 1;
    }
    mpc_XOR2(t0, g, z);

    return 0;
}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2])
{
    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2])
{
    z[0] = ~x[0];
    z[1] = ~x[1];
}

int verify(a a, int e, z z)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
    H(z.ke, z.ve, z.re, hash);

    if (memcmp(a.h[e], hash, 32) != 0)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    H(z.ke1, z.ve1, z.re1, hash);
    if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    free(hash);

    uint32_t *result = malloc(32);
    output(z.ve, result);
    if (memcmp(a.yp[e], result, 32) != 0)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }

    output(z.ve1, result);
    if (memcmp(a.yp[(e + 1) % 3], result, 32) != 0)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }

    free(result);

    int Bytes_Needed = 2912;
    unsigned char randomness[2][Bytes_Needed];
    getAllRandomness(z.ke, randomness[0], Bytes_Needed);
    getAllRandomness(z.ke1, randomness[1], Bytes_Needed);

    int *randCount = calloc(1, sizeof(int));
    int *countY = calloc(1, sizeof(int));

    uint32_t w[64][2];
    for (int j = 0; j < 16; j++)
    {
        w[j][0] = (z.ve.x[j * 4] << 24) | (z.ve.x[j * 4 + 1] << 16) | (z.ve.x[j * 4 + 2] << 8) | z.ve.x[j * 4 + 3];
        w[j][1] = (z.ve1.x[j * 4] << 24) | (z.ve1.x[j * 4 + 1] << 16) | (z.ve1.x[j * 4 + 2] << 8) | z.ve1.x[j * 4 + 3];
    }

    uint32_t s0[2], s1[2];
    uint32_t t0[2], t1[2];
    for (int j = 16; j < 64; j++)
    {
        // s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
        mpc_RIGHTROTATE2(w[j - 15], 7, t0);
        mpc_RIGHTROTATE2(w[j - 15], 18, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTSHIFT2(w[j - 15], 3, t1);
        mpc_XOR2(t0, t1, s0);

        // s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
        mpc_RIGHTROTATE2(w[j - 2], 17, t0);
        mpc_RIGHTROTATE2(w[j - 2], 19, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTSHIFT2(w[j - 2], 10, t1);
        mpc_XOR2(t0, t1, s1);

        // w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

        if (mpc_ADD_verify(w[j - 16], s0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }

        if (mpc_ADD_verify(w[j - 7], t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }
        if (mpc_ADD_verify(t1, s1, w[j], z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }
    }

    uint32_t va[2] = {hA[0], hA[0]};
    uint32_t vb[2] = {hA[1], hA[1]};
    uint32_t vc[2] = {hA[2], hA[2]};
    uint32_t vd[2] = {hA[3], hA[3]};
    uint32_t ve[2] = {hA[4], hA[4]};
    uint32_t vf[2] = {hA[5], hA[5]};
    uint32_t vg[2] = {hA[6], hA[6]};
    uint32_t vh[2] = {hA[7], hA[7]};
    uint32_t temp1[3], temp2[3], maj[3];
    for (int i = 0; i < 64; i++)
    {
        // s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
        mpc_RIGHTROTATE2(ve, 6, t0);
        mpc_RIGHTROTATE2(ve, 11, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTROTATE2(ve, 25, t1);
        mpc_XOR2(t0, t1, s1);

        // ch = (e & f) ^ ((~e) & g);
        // temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

        // t0 = h + s1

        if (mpc_ADD_verify(vh, s1, t0, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        if (mpc_CH_verify(ve, vf, vg, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // t1 = t0 + t1 (h+s1+ch)
        if (mpc_ADD_verify(t0, t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        t0[0] = k[i];
        t0[1] = k[i];
        if (mpc_ADD_verify(t1, t0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        if (mpc_ADD_verify(t1, w[i], temp1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
        mpc_RIGHTROTATE2(va, 2, t0);
        mpc_RIGHTROTATE2(va, 13, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTROTATE2(va, 22, t1);
        mpc_XOR2(t0, t1, s0);

        // maj = (a & (b ^ c)) ^ (b & c);
        //(a & b) ^ (a & c) ^ (b & c)

        if (mpc_MAJ_verify(va, vb, vc, maj, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // temp2 = s0+maj;
        if (mpc_ADD_verify(s0, maj, temp2, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        memcpy(vh, vg, sizeof(uint32_t) * 2);
        memcpy(vg, vf, sizeof(uint32_t) * 2);
        memcpy(vf, ve, sizeof(uint32_t) * 2);
        // e = d+temp1;
        if (mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        memcpy(vd, vc, sizeof(uint32_t) * 2);
        memcpy(vc, vb, sizeof(uint32_t) * 2);
        memcpy(vb, va, sizeof(uint32_t) * 2);
        // a = temp1+temp2;

        if (mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }
    }

    uint32_t hHa[8][3] = {{hA[0], hA[0], hA[0]}, {hA[1], hA[1], hA[1]}, {hA[2], hA[2], hA[2]}, {hA[3], hA[3], hA[3]},
                          {hA[4], hA[4], hA[4]}, {hA[5], hA[5], hA[5]}, {hA[6], hA[6], hA[6]}, {hA[7], hA[7], hA[7]}};
    if (mpc_ADD_verify(hHa[0], va, hHa[0], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[1], vb, hHa[1], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[2], vc, hHa[2], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[3], vd, hHa[3], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[4], ve, hHa[4], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[5], vf, hHa[5], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[6], vg, hHa[6], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[7], vh, hHa[7], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }

    free(randCount);
    free(countY);

    return 0;
}
