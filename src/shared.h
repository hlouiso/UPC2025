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

extern const int COMMIT_KEY_LEN;
extern const int COMMIT_LEN;
extern const int NUM_ROUNDS;
extern const int mpc_sha256_size;
extern const int mpc_sha256_runs;
extern int ySize;
extern const int output_nb_in_uint32;
extern int Random_Bytes_Needed;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1 << (i)) : (x) & (~(1 << (i)))

/* 8247 bytes = COMMIT_KEY_LEN (23 bytes) + Digest len (32 bytes) + Sigma size (wots signature: 256 * 32 bytes) */
extern const int INPUT_LEN;

static const uint32_t hA[8];

static const uint32_t k[64];

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

extern omp_lock_t *locks;

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