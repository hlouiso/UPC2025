/*
 ============================================================================
 Name        : MPC_SHA256_VERIFIER.c
 Author      : Sobuno
 Version     : 0.1
 Description : Verifies a proof for SHA-256 generated by MPC_SHA256.c
 ============================================================================
 */

#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int NUM_ROUNDS = 136;

void printbits(uint32_t n)
{
    if (n)
    {
        printbits(n >> 1);
        printf("%d", n & 1);
    }
}

int main(void)
{
    setbuf(stdout, NULL);
    init_EVP();
    openmp_thread_setup();

    printf("Iterations of SHA: %d\n", NUM_ROUNDS);

    a as[NUM_ROUNDS];
    z zs[NUM_ROUNDS];
    FILE *file;

    char outputFile[3 * sizeof(int) + 8];
    sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
    file = fopen(outputFile, "rb");
    if (!file)
    {
        printf("Unable to open file!");
    }
    fread(&as, sizeof(a), NUM_ROUNDS, file);
    fread(&zs, sizeof(z), NUM_ROUNDS, file);
    fclose(file);

    uint32_t y[8];
    reconstruct(as[0].yp[0], as[0].yp[1], as[0].yp[2], y);
    printf("Proof for hash: ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X", y[i]);
    }
    printf("\n");
    printf("Loading files\n");

    int es[NUM_ROUNDS];
    H3(y, as, NUM_ROUNDS, es);
    printf("Generating E\n");

#pragma omp parallel for
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        int verifyResult = verify(as[i], es[i], zs[i]);
        if (verifyResult != 0)
        {
            printf("Not Verified %d\n", i);
        }
    }
    printf("Verified well !\n");
    openmp_thread_cleanup();
    cleanup_EVP();
    return EXIT_SUCCESS;
}
