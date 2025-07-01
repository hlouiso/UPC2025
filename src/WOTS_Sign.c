#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEED_LEN 32
#define NUM_BITS 256

static int hexval(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('A' <= c && c <= 'F')
        return 10 + (c - 'A');
    return -1; /* invalid */
}

static void write_hex_line(FILE *fp, const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        fprintf(fp, "%02X", data[i]);
    fputc('\n', fp);
}

int main(void)
{
    char hex_input[65] = {0};
    int bits[NUM_BITS] = {0};

    printf("Entrez le commitment en hexadécimal MAJUSCULE (64 caractères) : ");
    if (scanf("%64s", hex_input) != 1)
    {
        fprintf(stderr, "Erreur : lecture impossible.\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < 64; ++i)
    {
        int v = hexval(hex_input[i]);
        for (int b = 0; b < 4; ++b)
            bits[i * 4 + b] = (v >> (3 - b)) & 1;
    }

    unsigned char priv[NUM_BITS][SEED_LEN];
    unsigned char pub[NUM_BITS][SHA256_DIGEST_LENGTH];

    for (int i = 0; i < NUM_BITS; ++i)
    {
        if (RAND_bytes(priv[i], SEED_LEN) != 1)
        {
            fprintf(stderr, "Erreur : RAND_bytes a échoué.\n");
            return EXIT_FAILURE;
        }
        SHA256(priv[i], SEED_LEN, pub[i]);
    }

    FILE *fp = fopen("signature.txt", "w");
    for (int i = 0; i < NUM_BITS; ++i)
    {
        if (bits[i] == 0)
            write_hex_line(fp, priv[i], SEED_LEN);
        else
            write_hex_line(fp, pub[i], SHA256_DIGEST_LENGTH);
    }
    fclose(fp);

    fp = fopen("public_key.txt", "w");
    for (int i = 0; i < NUM_BITS; ++i)
        write_hex_line(fp, pub[i], SHA256_DIGEST_LENGTH);

    fclose(fp);
    puts("signature.txt generated.\n");
    return EXIT_SUCCESS;
}
