#include "MPC_verify_functions.h"
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

    // Getting m
    char *message = NULL;
    size_t bufferSize = 0;
    printf("\nPlease enter your message:\n");
    getline(&message, &bufferSize, stdin);
    message[strlen(message) - 1] = '\0'; // to remove '\n' at the end
    printf("\n");

    // Computing message digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), digest);
    free(message);

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

    // Verifying Circuit Output
    uint32_t xor_val;
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        for (int j = 0; j < 257 * 8; j++)
        {
            xor_val = as[i].yp[0][j] ^ as[i].yp[1][j] ^ as[i].yp[2][j];
            if (xor_val != 0)
            {
                printf("Unexpected non-zero output at round %d\n", xor_val);
                fprintf(stderr, "Error: invalid signature\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    int es[NUM_ROUNDS];
    H3(digest, as, NUM_ROUNDS, es);
    bool error = false;

#pragma omp parallel for
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        verify(digest, &error, as[i], es[i], zs[i]);
    }

    openmp_thread_cleanup();
    cleanup_EVP();
    printf("================================================================\n");
    if (error)
    {
        fprintf(stderr, "Error: invalid signature\n");
        exit(EXIT_FAILURE);
    }
    printf("\nProof verified successfully.\n\n");
    return EXIT_SUCCESS;
}
