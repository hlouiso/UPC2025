#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    setbuf(stdout, NULL);
    init_EVP();
    openmp_thread_setup();

    printf("Iterations of SHA: %d\n", NUM_ROUNDS);

    FILE *file;

    char outputFile[3 * sizeof(int) + 8];
    sprintf(outputFile, "proof.bin");
    file = fopen(outputFile, "rb");

    /* ============================================== Reading Proof ============================================== */
    a *as = malloc(NUM_ROUNDS * sizeof(a));
    z *zs = malloc(NUM_ROUNDS * sizeof(z));

    fread(as, sizeof(a), NUM_ROUNDS, file);
    for (int i = 0; i < NUM_ROUNDS; ++i)
    {
        fread(&zs[i], sizeof(z), 1, file);

        zs[i].ve.y = malloc(ySize * sizeof(uint32_t));
        zs[i].ve1.y = malloc(ySize * sizeof(uint32_t));

        fread(zs[i].ve.y, sizeof(uint32_t), ySize, file);
        fread(zs[i].ve1.y, sizeof(uint32_t), ySize, file);
    }

    fclose(file);
    /* ============================================================================================================= */

    uint32_t y[8];
    reconstruct(as[0].yp[0], as[0].yp[1], as[0].yp[2], y);
    printf("\nProof for hash:\n");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X", y[i]);
    }
    printf("\n\n");

    int es[NUM_ROUNDS];
    H3(y, as, NUM_ROUNDS, es);

    bool consistent;
    consistent = true;
#pragma omp parallel for
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        int verifyResult = verify(as[i], es[i], zs[i]);
        if (verifyResult != 0)
        {
            printf("Not Verified, round %d is inconsistent\n", i);
            consistent = false;
        }
    }

    if (consistent)
    {
        printf("Verified well !\n");
    }
    openmp_thread_cleanup();
    cleanup_EVP();
    return EXIT_SUCCESS;
}
