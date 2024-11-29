#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

// Constants for password hashing
#define SALT_LENGTH 16
#define HASH_LENGTH 64
#define ITERATIONS 100000

// Password length constraints
#define PASSWORD_MIN_LEN 8
#define PASSWORD_MAX_LEN 64

// Function Prototypes

/**
 * @brief Generates a hashed password using PBKDF2-HMAC-SHA256.
 * 
 * @param password The plaintext password to hash.
 * @return A dynamically allocated string containing the hash in the format
 *         "salt:hash" (hexadecimal). Returns NULL on failure.
 *         Caller must free the returned string.
 */
char *generate_password_hash(const char *password);

/**
 * @brief Validates a password against complexity requirements.
 * 
 * @param password The plaintext password to validate.
 * @return 1 if the password meets complexity requirements, 0 otherwise.
 */
int validate_password(const char *password);

/**
 * @brief Verifies a plaintext password against a stored hash.
 * 
 * @param password The plaintext password to verify.
 * @param stored_hash The stored hash in the format "salt:hash" (hexadecimal).
 * @return 1 if the password matches the hash, 0 otherwise.
 */
int verify_password(const char *password, const char *stored_hash);

#endif // AUTH_H
