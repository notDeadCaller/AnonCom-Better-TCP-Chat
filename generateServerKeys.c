#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

// Choose your Dilithium security level (2, 3, or 5)
#define DILITHIUM_ALG OQS_SIG_alg_ml_dsa_65

int main() {
    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG);
    if (!sig) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed for %s\n", DILITHIUM_ALG);
        return 1;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    if (!public_key || !secret_key) {
        fprintf(stderr, "ERROR: malloc failed\n");
        return 1;
    }

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {    // Generate the keypair
        fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
        return 1;
    }

    FILE *f_pk = fopen("server_dilithium.pub", "wb");	    // --- Save keys to files ---
    if (!f_pk) { perror("fopen server_dilithium.pub"); return 1; }
    fwrite(public_key, 1, sig->length_public_key, f_pk);
    fclose(f_pk);

    FILE *f_sk = fopen("server_dilithium.key", "wb");
    if (!f_sk) { perror("fopen server_dilithium.key"); return 1; }
    fwrite(secret_key, 1, sig->length_secret_key, f_sk);
    fclose(f_sk);

    // --- Print the public key as a C array for the client ---
    printf("// Server public verification key (%s - %zu bytes):\n", DILITHIUM_ALG, sig->length_public_key);
    printf("const uint8_t HARDCODED_SERVER_PUB_KEY[] = {\n    ");
    for(size_t i = 0; i < sig->length_public_key; i++) {
        printf("0x%02x, ", public_key[i]);
        if ((i + 1) % 12 == 0 && (i + 1) < sig->length_public_key) printf("\n    ");
    }
    printf("\n};\n");
    printf("const size_t HARDCODED_SERVER_PUB_KEY_LEN = %zu;\n", sig->length_public_key);

    printf("\nGenerated server_dilithium.pub and server_dilithium.key\n");

    free(public_key);
    free(secret_key);
    OQS_SIG_free(sig);
    return 0;
}
