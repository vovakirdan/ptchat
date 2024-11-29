#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "auth.h"

// Generates a hashed password using PBKDF2-HMAC-SHA256
char *generate_password_hash(const char *password) {
    if (!password) return NULL;

    // Generate random salt
    unsigned char salt[SALT_LENGTH];
    if (!RAND_bytes(salt, SALT_LENGTH)) {
        fprintf(stderr, "Error generating salt.\n");
        return NULL;
    }

    // Derive the hash
    unsigned char hash[HASH_LENGTH];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH,
                           ITERATIONS, EVP_sha256(), HASH_LENGTH, hash)) {
        fprintf(stderr, "Error deriving hash with PBKDF2.\n");
        return NULL;
    }

    // Allocate memory for result: "salt:hash" in hex format
    size_t result_len = SALT_LENGTH * 2 + HASH_LENGTH * 2 + 2;
    char *result = malloc(result_len);
    if (!result) {
        fprintf(stderr, "Error allocating memory for hash result.\n");
        return NULL;
    }

    // Convert salt and hash to hexadecimal and store in result
    char *ptr = result;
    for (int i = 0; i < SALT_LENGTH; i++) sprintf(ptr + i * 2, "%02x", salt[i]);
    ptr += SALT_LENGTH * 2;
    *ptr++ = ':';
    for (int i = 0; i < HASH_LENGTH; i++) sprintf(ptr + i * 2, "%02x", hash[i]);
    result[result_len - 1] = '\0';

    return result;
}

// Validates a password against complexity requirements
int validate_password(const char *password) {
    if (!password) return 0;

    size_t len = strlen(password);
    if (len < PASSWORD_MIN_LEN || len > PASSWORD_MAX_LEN) return 0;

    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;

    for (size_t i = 0; i < len; i++) {
        if (isupper(password[i])) has_upper = 1;
        else if (islower(password[i])) has_lower = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else if (ispunct(password[i])) has_special = 1;
    }

    return has_upper && has_lower && has_digit && has_special;
}

// Verifies a plaintext password against a stored hash
int verify_password(const char *password, const char *stored_hash) {
    if (!password || !stored_hash) return 0;

    // Split the stored hash into salt and hash parts
    const char *delimiter = strchr(stored_hash, ':');
    if (!delimiter) return 0;

    size_t salt_len = delimiter - stored_hash;
    size_t hash_len = strlen(stored_hash) - salt_len - 1;
    if (salt_len != SALT_LENGTH * 2 || hash_len != HASH_LENGTH * 2) return 0;

    // Extract salt from the stored hash
    unsigned char salt[SALT_LENGTH];
    for (size_t i = 0; i < SALT_LENGTH; i++) {
        sscanf(stored_hash + i * 2, "%2hhx", &salt[i]);
    }

    // Compute hash for the given password using the extracted salt
    unsigned char derived_hash[HASH_LENGTH];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH,
                           ITERATIONS, EVP_sha256(), HASH_LENGTH, derived_hash)) {
        fprintf(stderr, "Error deriving hash for verification.\n");
        return 0;
    }

    // Compare the derived hash with the stored hash
    char derived_hash_hex[HASH_LENGTH * 2 + 1];
    for (size_t i = 0; i < HASH_LENGTH; i++) {
        sprintf(derived_hash_hex + i * 2, "%02x", derived_hash[i]);
    }

    return strcmp(delimiter + 1, derived_hash_hex) == 0;
}

// int main() {
//     const char *password = "SecureP@ssw0rd!";
//     printf("Validating password: %s\n", validate_password(password) ? "Valid" : "Invalid");

//     char *hash = generate_password_hash(password);
//     if (hash) {
//         printf("Generated hash: %s\n", hash);
//         printf("Verifying password: %s\n", verify_password(password, hash) ? "Match" : "Mismatch");
//         free(hash);
//     } else {
//         printf("Hash generation failed.\n");
//     }

//     return 0;
// }
