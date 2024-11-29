#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

// Utility Functions

/**
 * @brief Get the current timestamp as a string.
 *
 * @return A dynamically allocated string containing the current timestamp.
 *         Caller must free the returned string.
 */
char *get_current_timestamp(void);

/**
 * @brief Checks if a string is alphanumeric (letters, numbers, or hyphen).
 *
 * @param str The string to check.
 * @return true if the string is alphanumeric, false otherwise.
 */
bool is_alphanumeric(const char *str);

/**
 * @brief Trims leading and trailing whitespace from a string.
 *
 * @param str The string to trim.
 * @return A pointer to the trimmed string (modifies the input string).
 */
char *trim_whitespace(char *str);

/**
 * @brief Concatenates two strings into a new dynamically allocated string.
 *
 * @param str1 The first string.
 * @param str2 The second string.
 * @return A dynamically allocated string containing the concatenation of str1 and str2.
 *         Caller must free the returned string.
 */
char *concat_strings(const char *str1, const char *str2);

/**
 * @brief Safely reallocates memory, ensuring the original pointer is not lost on failure.
 *
 * @param ptr A pointer to the memory to reallocate.
 * @param size The new size in bytes.
 * @return A pointer to the reallocated memory, or NULL on failure.
 */
void *safe_realloc(void *ptr, size_t size);

#endif // UTILS_H
