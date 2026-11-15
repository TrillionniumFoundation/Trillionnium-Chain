/* Test-only adapter for the pinned mldsa-native v2.0.0 implementation.
 * No production verifier, key custody, RNG, or application authority lives here.
 * Signing accepts only a disposable repeated-byte seed. The native library's
 * deterministic internal API receives the FIPS 204 pure-mode prefix (0, ctxlen,
 * ctx), zero signing randomness, and externalmu=0. Verification uses its public
 * pure-mode API. Binary lengths are checked before either fixed-size C API.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mldsa_native.h"

#define PUBLIC_BYTES MLDSA_PUBLICKEYBYTES(65)
#define SECRET_BYTES MLDSA_SECRETKEYBYTES(65)
#define SIGNATURE_BYTES MLDSA_BYTES(65)
#define MESSAGE_LIMIT 65537u

static int read_field(uint8_t *out, size_t capacity, size_t *length)
{
    uint8_t size[4];
    uint32_t value;
    if (fread(size, 1, sizeof(size), stdin) != sizeof(size)) return 0;
    value = ((uint32_t)size[0] << 24) | ((uint32_t)size[1] << 16) |
            ((uint32_t)size[2] << 8) | (uint32_t)size[3];
    if (value > capacity || fread(out, 1, value, stdin) != value) return 0;
    *length = value;
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t context[256], message[MESSAGE_LIMIT];
    uint8_t public_key[PUBLIC_BYTES + 1], signature[SIGNATURE_BYTES + 1];
    size_t context_length, message_length, public_length, signature_length;
    int result;
    if (argc < 2 || !read_field(context, sizeof(context), &context_length) ||
        !read_field(message, sizeof(message), &message_length)) return 2;
    if (strcmp(argv[1], "sign") == 0 && argc == 3) {
        uint8_t seed[MLDSA_SEEDBYTES], secret_key[SECRET_BYTES];
        uint8_t random[MLDSA_RNDBYTES] = {0}, prefix[257];
        char *end = NULL;
        unsigned long number = strtoul(argv[2], &end, 10);
        if (argv[2][0] == '\0' || *end != '\0' || number > 255 ||
            context_length > 255 || fgetc(stdin) != EOF || ferror(stdin)) return 2;
        memset(seed, (int)number, sizeof(seed));
        prefix[0] = 0;
        prefix[1] = (uint8_t)context_length;
        memcpy(prefix + 2, context, context_length);
        result = trnm_test_mldsa_keypair_internal(public_key, secret_key, seed);
        if (result != 0) return 3;
        result = trnm_test_mldsa_signature_internal(signature, message,
            message_length, prefix, context_length + 2, random, secret_key, 0);
        if (result != 0) return 3;
        if (fwrite(public_key, 1, PUBLIC_BYTES, stdout) != PUBLIC_BYTES ||
            fwrite(signature, 1, SIGNATURE_BYTES, stdout) != SIGNATURE_BYTES)
            return 4;
    } else if (strcmp(argv[1], "verify") == 0 && argc == 2) {
        if (!read_field(public_key, sizeof(public_key), &public_length) ||
            !read_field(signature, sizeof(signature), &signature_length) ||
            fgetc(stdin) != EOF || ferror(stdin)) return 2;
        result = 0;
        if (public_length == PUBLIC_BYTES && signature_length == SIGNATURE_BYTES &&
            context_length <= 255) {
            result = trnm_test_mldsa_verify(signature, message, message_length,
                context, context_length, public_key) == 0;
        }
        if (fputc(result ? 1 : 0, stdout) == EOF) return 4;
    } else {
        return 2;
    }
    return fflush(stdout) == 0 ? 0 : 4;
}
