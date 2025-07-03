CC = gcc
OPENSSL_DIR = ../third_party/openssl/openssl-1.0.2l

CFLAGS  = -O2 -Wall -fopenmp -I$(OPENSSL_DIR)/include
LDFLAGS = -fopenmp $(OPENSSL_DIR)/libssl.a $(OPENSSL_DIR)/libcrypto.a -ldl

all: ../prover ../verifier ../sign

../prover: prover.o shared.o MPC_prove_functions.o building_views.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

shared.o: shared.c shared.h
	$(CC) $(CFLAGS) -c $< -o $@

prover.o: prover.c shared.h MPC_prove_functions.h building_views.h
	$(CC) $(CFLAGS) -c $< -o $@

MPC_prove_functions.o: MPC_prove_functions.c MPC_prove_functions.h shared.h
	$(CC) $(CFLAGS) -c $< -o $@

building_views.o: building_views.c building_views.h MPC_prove_functions.h shared.h
	$(CC) $(CFLAGS) -c $< -o $@

../verifier: MPC_SHA256_VERIFIER.o shared.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

MPC_SHA256_VERIFIER.o: MPC_SHA256_VERIFIER.c shared.h
	$(CC) $(CFLAGS) -c $< -o $@

../sign: WOTS_Sign.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o src/*.o ../prover ../verifier ../sign ../out* ../proof.bin
