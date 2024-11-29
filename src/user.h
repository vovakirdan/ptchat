#ifndef USER_H
#define USER_H

#include <stddef.h>
#include <stdbool.h>
#include "../cbinc/dict.h"

// Constants for user UID
#define UID_MIN_LEN 4
#define UID_MAX_LEN 64

// Constants for password length
#define PASSWORD_MIN_LEN 8
#define PASSWORD_MAX_LEN 64

// User Entry Structure
typedef struct {
    char *user_uid;     // Unique ID for the user
    char *pass_hash;    // Hashed password
    int user_status;    // 0 - offline, 1 - online
} user_entry;

/**
 * @brief Initializes a user entry.
 *
 * @param uid The unique ID for the user.
 * @param hash The hashed password for the user.
 * @return A pointer to the initialized `user_entry`. Caller must free.
 */
user_entry *user_entry_init(const char *uid, const char *hash);

/**
 * @brief Frees a user entry.
 *
 * @param entry The user entry to free.
 */
void user_entry_free(user_entry *entry);

// User Database Structure
typedef struct {
    struct dict(user_entry) user_db;  // Dictionary of user entries
    char *user_list_fmt;             // Formatted user list string
} user_database;

/**
 * @brief Initializes a user database.
 *
 * @return A pointer to the initialized `user_database`. Caller must free.
 */
user_database *user_db_init(void);

/**
 * @brief Frees a user database.
 *
 * @param db The user database to free.
 */
void user_db_free(user_database *db);

/**
 * @brief Adds a new user to the database.
 *
 * @param db The user database.
 * @param uid The unique ID for the user.
 * @param password The plaintext password for the user.
 * @return true if the user was successfully added, false otherwise.
 */
bool user_db_add(user_database *db, const char *uid, const char *password);

/**
 * @brief Checks if a user exists in the database.
 *
 * @param db The user database.
 * @param uid The unique ID to check.
 * @return true if the user exists, false otherwise.
 */
bool user_db_contains(user_database *db, const char *uid);

/**
 * @brief Validates a user's password.
 *
 * @param db The user database.
 * @param uid The unique ID for the user.
 * @param password The plaintext password to validate.
 * @return true if the password matches, false otherwise.
 */
bool user_db_validate_password(user_database *db, const char *uid, const char *password);

/**
 * @brief Retrieves the list of users in the database.
 *
 * @param db The user database.
 * @param show_status Whether to include online/offline status in the list.
 * @return A dynamically allocated string containing the user list. Caller must free.
 */
char *user_db_get_list(user_database *db, bool show_status);

/**
 * @brief Sets a user's online/offline status.
 *
 * @param db The user database.
 * @param uid The unique ID for the user.
 * @param status 0 for offline, 1 for online.
 */
void user_db_set_status(user_database *db, const char *uid, int status);

#endif // USER_H
