#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "utils.h"

// Get the current timestamp as a string
char *get_current_timestamp(void) {
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);

    if (!local_time) {
        fprintf(stderr, "Error retrieving local time.\n");
        return NULL;
    }

    char *timestamp = malloc(20); // Format: "YYYY-MM-DD HH:MM:SS"
    if (!timestamp) {
        fprintf(stderr, "Error allocating memory for timestamp.\n");
        return NULL;
    }

    snprintf(timestamp, 20, "%04d-%02d-%02d %02d:%02d:%02d",
             local_time->tm_year + 1900, local_time->tm_mon + 1,
             local_time->tm_mday, local_time->tm_hour, local_time->tm_min,
             local_time->tm_sec);

    return timestamp;
}

// Check if a string is alphanumeric
bool is_alphanumeric(const char *str) {
    if (!str || *str == '\0') return false;

    for (size_t i = 0; str[i] != '\0'; i++) {
        if (!isalnum(str[i]) && str[i] != '-') {
            return false;
        }
    }
    return true;
}

// Trim leading and trailing whitespace from a string
char *trim_whitespace(char *str) {
    if (!str) return NULL;

    char *end;

    // Trim leading whitespace
    while (isspace((unsigned char)*str)) str++;

    // If all spaces, return empty string
    if (*str == '\0') return str;

    // Trim trailing whitespace
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write the null terminator
    *(end + 1) = '\0';

    return str;
}

// Concatenate two strings into a new dynamically allocated string
char *concat_strings(const char *str1, const char *str2) {
    if (!str1 || !str2) return NULL;

    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    char *result = malloc(len1 + len2 + 1);
    if (!result) {
        fprintf(stderr, "Error allocating memory for concatenated string.\n");
        return NULL;
    }

    strcpy(result, str1);
    strcat(result, str2);

    return result;
}

// Safely reallocate memory
void *safe_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Error reallocating memory.\n");
        free(ptr); // Free the original memory block to avoid leaks
        return NULL;
    }
    return new_ptr;
}

// int main() {
//     // Test timestamp
//     char *timestamp = get_current_timestamp();
//     printf("Timestamp: %s\n", timestamp);
//     free(timestamp);

//     // Test is_alphanumeric
//     printf("Is Alphanumeric (valid): %d\n", is_alphanumeric("user-123"));
//     printf("Is Alphanumeric (invalid): %d\n", is_alphanumeric("user@123"));

//     // Test trim_whitespace
//     char str[] = "   Hello, World!   ";
//     printf("Trimmed String: '%s'\n", trim_whitespace(str));

//     // Test concat_strings
//     char *concat = concat_strings("Hello, ", "World!");
//     printf("Concatenated String: %s\n", concat);
//     free(concat);

//     return 0;
// }
