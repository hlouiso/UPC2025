CC = gcc
OPENSSL_DIR = ../third_party/openssl/openssl-1.0.2l

CFLAGS = -O2 -Wall -fopenmp -I$(OPENSSL_DIR)/include
LDFLAGS = -fopenmp $(OPENSSL_DIR)/libssl.a $(OPENSSL_DIR)/libcrypto.a -ldl

all: ../prover ../verifier

../prover: MPC_SHA256.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

../verifier: MPC_SHA256_VERIFIER.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o ../prover ../verifier ../out* ../proof.bin
