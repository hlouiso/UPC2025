#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf(
            "\nThis binary is used by anyone the verify the zero-knowledge proof of knowledge stored in 'proof.bin'.\n"
            "This proof is used as a blind signature for a WOTS signature of a secretly known 256 bits message "
            "commitment.\n");
        return 0;
    }

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

    // Getting public_key
    int c1;
    int c2;
    file = fopen("public_key.txt", "r");
    unsigned char public_key[8192];
    for (int i = 0; i < 256; ++i)
        for (int j = 0; j < 32; ++j)
        {
            c1 = fgetc(file);
            while (c1 == '\n')
            {
                c1 = fgetc(file);
            }

            c2 = fgetc(file);
            while (c2 == '\n')
            {
                c2 = fgetc(file);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            public_key[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    fclose(file);

    char outputFile[3 * sizeof(int) + 8];
    sprintf(outputFile, "proof.bin");
    file = fopen(outputFile, "rb");

    /* ============================================== Reading Proof ============================================== */
    a *as = malloc(NUM_ROUNDS * sizeof(a));
    z *zs = malloc(NUM_ROUNDS * sizeof(z));

    size_t items_read = fread(as, sizeof(a), NUM_ROUNDS, file);

    for (int i = 0; i < NUM_ROUNDS; ++i)
    {
        items_read = fread(&zs[i], sizeof(z), 1, file);

        zs[i].ve.y = malloc(ySize * sizeof(uint32_t));
        zs[i].ve1.y = malloc(ySize * sizeof(uint32_t));

        items_read = fread(zs[i].ve.y, sizeof(uint32_t), ySize, file);
        items_read = fread(zs[i].ve1.y, sizeof(uint32_t), ySize, file);
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
        verify(digest, public_key, &error, as[i], es[i], zs[i]);
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
