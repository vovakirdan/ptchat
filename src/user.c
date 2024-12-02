#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "user.h"
#include "auth.h"
#include "../cbinc/dict.h"

// Initialize a user entry
user_entry *user_entry_init(const char *uid, const char *hash) {
    user_entry *entry = malloc(sizeof(user_entry));
    if (!entry) {
        fprintf(stderr, "Error allocating memory for user entry.\n");
        return NULL;
    }

    entry->user_uid = strdup(uid);
    entry->pass_hash = strdup(hash);
    entry->user_status = 0; // Offline by default

    return entry;
}

// Free a user entry
void user_entry_free(user_entry *entry) {
    if (!entry) return;
    free(entry->user_uid);
    free(entry->pass_hash);
    free(entry);
}

// Initialize a user database
user_database *user_db_init(void) {
    user_database *db = malloc(sizeof(user_database));
    if (!db) {
        fprintf(stderr, "Error allocating memory for user database.\n");
        return NULL;
    }

    db->user_db = dict__create(user_entry);
    db->user_list_fmt = strdup(""); // Start with an empty list

    return db;
}

// Free a user database
void user_db_free(user_database *db) {
    if (!db) return;

    // Free items
    for (size_t i = 0; i < db->user_db.items.size; i++) {
        user_entry *entry = vector__access(user_entry, i, db->user_db.items);
        if (entry) user_entry_free(entry);
    }
    vector__destroy_(sizeof(user_entry), NULL, &db->user_db.items);

    // Free keys
    for (size_t i = 0; i < db->user_db.keys.size; i++) {
        struct slice(char) *key_slice = vector__access(struct slice(char), i, db->user_db.keys);
        if (key_slice && key_slice->data) {
            free(key_slice->data);
            key_slice->data = NULL;
            key_slice->size = 0;
        }
    }
    vector__destroy(struct slice(char), NULL, db->user_db.keys);

    free(db->user_list_fmt);
    free(db);
}

// Add a user to the database
bool user_db_add(user_database *db, const char *uid, const char *password) {
    if (!db || !uid || !password) return false;

    if (strlen(uid) < UID_MIN_LEN || strlen(uid) > UID_MAX_LEN) return false;
    if (strlen(password) < PASSWORD_MIN_LEN || strlen(password) > PASSWORD_MAX_LEN) return false;

    if (user_db_contains(db, uid)) return false; // User already exists

    char *hash = generate_password_hash(password);
    if (!hash) return false;

    user_entry *entry = user_entry_init(uid, hash);
    if (!entry) {
        free(hash);
        return false;
    }

    // Copy the UID for the key
    char *uid_copy = strdup(uid);
    if (!uid_copy) {
        fprintf(stderr, "Error allocating memory for UID copy.\n");
        free(hash);
        user_entry_free(entry);
        return false;
    }

    struct slice key = slice__create(char, uid_copy, strlen(uid_copy));
    dict__insert(user_entry, key, *entry, db->user_db);

    // Update formatted user list
    size_t new_list_size = strlen(db->user_list_fmt) + strlen(uid) + 2;
    db->user_list_fmt = realloc(db->user_list_fmt, new_list_size);
    strcat(db->user_list_fmt, uid);
    strcat(db->user_list_fmt, "\n");

    free(hash);
    // Do not free 'entry' since it's stored in the dictionary
    // Do not free 'uid_copy' since it's used in the dictionary

    return true;
}

// Check if a user exists in the database
bool user_db_contains(user_database *db, const char *uid) {
    if (!db || !uid) return false;

    struct slice key = slice__create(char, uid, strlen(uid));
    return dict__search(user_entry, key, db->user_db) != NULL;
}

// Validate a user's password
bool user_db_validate_password(user_database *db, const char *uid, const char *password) {
    if (!db || !uid || !password) return false;

    struct slice key = slice__create(char, uid, strlen(uid));
    user_entry *entry = dict__search(user_entry, key, db->user_db);

    if (!entry) return false; // User not found
    return verify_password(password, entry->pass_hash);
}

// Get the list of users
char *user_db_get_list(user_database *db, bool show_status) {
    if (!db) return NULL;

    if (!show_status) return strdup(db->user_list_fmt);

    size_t buffer_size = strlen(db->user_list_fmt) + 128;
    char *list_with_status = malloc(buffer_size);

    if (!list_with_status) {
        fprintf(stderr, "Error allocating memory for user list.\n");
        return NULL;
    }

    strcpy(list_with_status, "");

    for (size_t i = 0; i < db->user_db.keys.size; i++) {
        // const char *uid = (const char *)vector__access(char, i, db->user_db.keys.data);
        // user_entry *entry = dict__search(user_entry, slice__create(char, uid, strlen(uid)), db->user_db);
        struct slice(char) *key_slice = vector__access(struct slice(char), i, db->user_db.keys);
        if (!key_slice || !key_slice->data) continue;

        // const char *status = entry->user_status ? "online" : "offline";
        // size_t entry_size = strlen(uid) + strlen(status) + 16;
        const char *uid = key_slice->data;
        size_t uid_len = key_slice->size;

        // Retrieve the user entry
        user_entry *entry = dict__search(user_entry, *key_slice, db->user_db);
        if (!entry) continue; // Should not happen, but check anyway

        const char *status = entry->user_status ? "online" : "offline";
        size_t status_len = strlen(status);

        // Calculate required buffer size
        size_t entry_size = uid_len + status_len + 4; // For ": ", "\n", and null terminator

        if (strlen(list_with_status) + entry_size >= buffer_size) {
            buffer_size *= 2;
            list_with_status = realloc(list_with_status, buffer_size);
            if (!list_with_status) {
                fprintf(stderr, "Error reallocating memory for user list.\n");
                return NULL;
            }
        }

        strcat(list_with_status, uid);
        strcat(list_with_status, ": ");
        strcat(list_with_status, status);
        strcat(list_with_status, "\n");
    }

    return list_with_status;
}

// Set a user's online/offline status
void user_db_set_status(user_database *db, const char *uid, int status) {
    if (!db || !uid) return;

    struct slice key = slice__create(char, uid, strlen(uid));
    user_entry *entry = dict__search(user_entry, key, db->user_db);

    if (entry) entry->user_status = status;
}
