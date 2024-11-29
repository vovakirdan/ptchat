#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdbool.h>
#include <stddef.h>
#include "../cbinc/vector.h"
#include "network.h"

// Message types
#define MSG_PUBLIC 0
#define MSG_TAGGED 1
#define MSG_PRIVATE 2

// Constants
#define MSG_ATTR_LEN 3
#define MSG_ATTR_TO_USER "~->"
#define MSG_ATTR_TAG_USER "~-@"
#define MSG_DELIM ':'

// Message Attribute Struct
typedef struct {
    uint8_t msg_type;       // MSG_PUBLIC, MSG_TAGGED, MSG_PRIVATE
    char *target_uid;       // Target user UID (if any)
    size_t target_ctx_idx;  // Target context index (if any)
    bool is_valid;          // Whether attributes are valid
} msg_attr;

/**
 * @brief Initializes a message attribute structure.
 *
 * @return A pointer to the initialized `msg_attr` structure. Caller must free.
 */
msg_attr *msg_attr_init(void);

/**
 * @brief Resets a message attribute structure to default values.
 *
 * @param attr The `msg_attr` structure to reset.
 */
void msg_attr_reset(msg_attr *attr);

/**
 * @brief Frees a message attribute structure.
 *
 * @param attr The `msg_attr` structure to free.
 */
void msg_attr_free(msg_attr *attr);

/**
 * @brief Prechecks a message for its type (public, tagged, private).
 *
 * @param msg The received message buffer.
 * @param attr A pointer to `msg_attr` to store the detected attributes.
 * @return 1 if the message is valid, 0 otherwise.
 */
int msg_precheck(const char *msg, msg_attr *attr);

/**
 * @brief Updates a message buffer with a header and other attributes.
 *
 * @param buffer The message buffer to update.
 * @param attr The message attributes to apply.
 * @param ctx The connection context of the sender.
 * @return true if the buffer was updated successfully, false otherwise.
 */
bool update_msg_buffer(struct vector(char) *buffer, const msg_attr *attr, const conn_ctx *ctx);

/**
 * @brief Broadcasts a message to all connected clients.
 *
 * @param chatroom The chatroom structure.
 * @param include_self Whether to include the sender in the broadcast.
 * @param sender_uid The UID of the sender.
 * @param msg_body The message body to broadcast.
 * @return The number of clients who received the message.
 */
size_t system_broadcast(upd_chatroom *chatroom, bool include_self, const char *sender_uid, const char *msg_body);

/**
 * @brief Formats the current list of users into a message.
 *
 * @param chatroom The chatroom structure.
 * @return A dynamically allocated string containing the user list message.
 *         Caller must free the returned string.
 */
char *format_user_list(upd_chatroom *chatroom);

#endif // MESSAGE_H
