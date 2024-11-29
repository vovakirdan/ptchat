#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "message.h"
#include "network.h"
#include "../cbinc/vector.h"

// Initialize a message attribute structure
msg_attr *msg_attr_init(void) {
    msg_attr *attr = malloc(sizeof(msg_attr));
    if (!attr) {
        fprintf(stderr, "Error allocating memory for msg_attr.\n");
        return NULL;
    }
    attr->msg_type = MSG_PUBLIC;
    attr->target_uid = NULL;
    attr->target_ctx_idx = 0;
    attr->is_valid = false;
    return attr;
}

// Reset a message attribute structure
void msg_attr_reset(msg_attr *attr) {
    if (!attr) return;
    attr->msg_type = MSG_PUBLIC;
    free(attr->target_uid);
    attr->target_uid = NULL;
    attr->target_ctx_idx = 0;
    attr->is_valid = false;
}

// Free a message attribute structure
void msg_attr_free(msg_attr *attr) {
    if (!attr) return;
    free(attr->target_uid);
    free(attr);
}

// Precheck a message for type and attributes
int msg_precheck(const char *msg, msg_attr *attr) {
    if (!msg || !attr) return 0;

    msg_attr_reset(attr);

    if (strncmp(msg, MSG_ATTR_TO_USER, MSG_ATTR_LEN) == 0) {
        attr->msg_type = MSG_PRIVATE;
    } else if (strncmp(msg, MSG_ATTR_TAG_USER, MSG_ATTR_LEN) == 0) {
        attr->msg_type = MSG_TAGGED;
    } else {
        attr->msg_type = MSG_PUBLIC;
        attr->is_valid = true;
        return 1;
    }

    const char *uid_start = msg + MSG_ATTR_LEN;
    const char *delim = strchr(uid_start, MSG_DELIM);
    if (!delim) {
        fprintf(stderr, "Message format invalid: Missing delimiter.\n");
        return 0;
    }

    attr->target_uid = strndup(uid_start, delim - uid_start);
    if (!attr->target_uid) {
        fprintf(stderr, "Error allocating memory for target_uid.\n");
        return 0;
    }

    attr->is_valid = true;
    return 1;
}

// Assemble a message header
char *assemble_msg_header(const conn_ctx *ctx) {
    if (!ctx) return NULL;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ctx->conn_addr.sin_addr, ip_str, INET_ADDRSTRLEN);

    char *msg_header = malloc(128);
    if (!msg_header) {
        fprintf(stderr, "Error allocating memory for message header.\n");
        return NULL;
    }

    snprintf(msg_header, 128, "[%s:%d][UID:%s]", ip_str, ntohs(ctx->conn_addr.sin_port), ctx->conn_bind_uid);
    return msg_header;
}

// Update a message buffer
bool update_msg_buffer(struct vector(char) *buffer, const msg_attr *attr, const conn_ctx *ctx) {
    if (!buffer || !attr || !ctx) return false;

    char *msg_header = assemble_msg_header(ctx);
    if (!msg_header) return false;

    struct slice(char) header_slice = slice__create(char, msg_header, strlen(msg_header));
    vector__insert(char, (char *)vector__begin(char, *buffer), header_slice, buffer);
    vector__push_back(char, '\n', buffer);
    vector__push_back(char, '\0', buffer);

    free(msg_header);
    return true;
}

// Broadcast a message to all connected clients
size_t system_broadcast(upd_chatroom *chatroom, bool include_self, const char *sender_uid, const char *msg_body) {
    if (!chatroom || !sender_uid || !msg_body) return 0;

    size_t sent_count = 0;

    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients);

        if (ctx->conn_status == 6 && (include_self || strcmp(ctx->conn_bind_uid, sender_uid) != 0)) {
            char msg[256];
            snprintf(msg, sizeof(msg), "[BROADCAST][%s]: %s", sender_uid, msg_body);

            if (simple_send(chatroom, msg, strlen(msg), ctx->conn_addr) >= 0) {
                sent_count++;
            }
        }
    }

    return sent_count;
}

// Format the user list into a message
char *format_user_list(upd_chatroom *chatroom) {
    if (!chatroom) return NULL;

    size_t buffer_size = 256;
    char *user_list = malloc(buffer_size);
    if (!user_list) {
        fprintf(stderr, "Error allocating memory for user list message.\n");
        return NULL;
    }

    snprintf(user_list, buffer_size, "Currently signed-in users:\n");

    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients);

        char user_status[32];
        snprintf(user_status, sizeof(user_status), "%s: %s\n", ctx->conn_bind_uid, ctx->conn_status == 6 ? "online" : "offline");

        if (strlen(user_list) + strlen(user_status) >= buffer_size) {
            buffer_size *= 2;
            user_list = realloc(user_list, buffer_size);
            if (!user_list) {
                fprintf(stderr, "Error reallocating memory for user list message.\n");
                return NULL;
            }
        }

        strcat(user_list, user_status);
    }

    return user_list;
}
