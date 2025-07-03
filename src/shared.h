#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "omp.h"

#define VERBOSE FALSE

const int COMMIT_KEY_LEN = 23;
const int COMMIT_LEN = 32;
const int NUM_ROUNDS = 1; // Usually 136
const mpc_sha256_size = 736;
const int mpc_sha256_runs = 257;
int ySize = mpc_sha256_runs * mpc_sha256_size + 8 + 24 * 256;
const int output_nb_in_uint32 = 257 * 8; // knowing that one output = 256 bits = 8 uint32_t
int Random_Bytes_Needed = 2912 * mpc_sha256_runs + 256 * 8 * 4;

/* 8247 bytes = COMMIT_KEY_LEN (23 bytes) + Digest len (32 bytes) + Sigma size (wots signature: 256 * 32 bytes) */
const int INPUT_LEN = 8247;

static const uint32_t hA[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct
{
    unsigned char x[8247];
    uint32_t *y;
} View;

typedef struct
{
    uint32_t yp[3][257 * 8];
    unsigned char h[3][32];
} a;

typedef struct
{
    unsigned char ke[16];
    unsigned char ke1[16];
    View ve;
    View ve1;
    unsigned char re[4];
    unsigned char re1[4];
} z;

void printbits(uint32_t n);

void handleErrors(void);

EVP_CIPHER_CTX setupAES(unsigned char key[16]);

void getAllRandomness(unsigned char key[16], unsigned char *randomness, int Bytes_Needed);

uint32_t getRandom32(unsigned char randomness[Random_Bytes_Needed], int randCount);

void init_EVP();

void cleanup_EVP();

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(uint32_t y[8], a *as, int s, int *es);

void output(View v, uint32_t *result);

void reconstruct(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *result);

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]);

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]);

omp_lock_t *locks;

void openmp_locking_callback(int mode, int type, char *file, int line);

unsigned long openmp_thread_id(void);

void openmp_thread_setup(void);

void openmp_thread_cleanup(void);

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][2912],
                   int *randCount, int *countY);

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][2912],
                   int *randCount, int *countY);

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]);

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]);

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1,
                   unsigned char randomness[2][2912], int *randCount, int *countY);

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1,
                  unsigned char randomness[2][2912], int *randCount, int *countY);

int verify(a a, int e, z z);

#endif // SHARED_H