#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "network.h"

conn_ctx *conn_ctx_init(struct sockaddr_in conn_addr, char *conn_bind_uid, int conn_status) {
    conn_ctx *ctx = malloc(sizeof(conn_ctx));
    if (!ctx) {
        fprintf(stderr, "Error allocating memory for conn_ctx.\n");
        return NULL;
    }
    ctx->conn_addr = conn_addr;
    ctx->conn_bind_uid = conn_bind_uid ? strdup(conn_bind_uid) : NULL;
    ctx->conn_status = conn_status;
    return ctx;
}

void conn_ctx_free(conn_ctx *ctx) {
    if (!ctx) return;
    free(ctx->conn_bind_uid);
    free(ctx);
}

upd_chatroom *upd_chatroom_init(uint16_t port, size_t buff_size) {
    upd_chatroom *chatroom = malloc(sizeof(upd_chatroom));
    if (!chatroom) {
        fprintf(stderr, "Error allocating memory for chatroom.\n");
        return NULL;
    }

    chatroom->server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (chatroom->server_fd < 0) {
        fprintf(stderr, "Error creating socket.\n");
        free(chatroom);
        return NULL;
    }

    chatroom->address.sin_family = AF_INET;
    chatroom->address.sin_addr.s_addr = INADDR_ANY;
    chatroom->address.sin_port = htons(port);
    chatroom->port = port;
    chatroom->buff_size = buff_size;
    chatroom->err_code = 0;
    chatroom->clients = vector__create(conn_ctx);

    return chatroom;
}

void upd_chatroom_free(upd_chatroom *chatroom) {
    if (!chatroom) return;

    close(chatroom->server_fd);
    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients);
        conn_ctx_free(ctx);
    }
    vector__destroy(conn_ctx, NULL, chatroom->clients);
    free(chatroom);
}

int simple_send(upd_chatroom *chatroom, const void *buff, size_t n, struct sockaddr_in client_addr) {
    return sendto(chatroom->server_fd, buff, n, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
}

// Find the index of a connection by client address
size_t get_conn_idx(upd_chatroom *chatroom, struct sockaddr_in client_addr) {
    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients);

        if (ctx->conn_addr.sin_addr.s_addr == client_addr.sin_addr.s_addr &&
            ctx->conn_addr.sin_port == client_addr.sin_port) {
            return i;
        }
    }
    return -1; // Client not found
}

// Clear a connection context
void clear_conn(conn_ctx *ctx) {
    if (!ctx) return;

    if (ctx->conn_bind_uid) {
        free(ctx->conn_bind_uid);
        ctx->conn_bind_uid = NULL;
    }

    ctx->conn_status = 0; // Mark as cleared
    memset(&ctx->conn_addr, 0, sizeof(ctx->conn_addr)); // Clear address
}

// Find the index of a client by their UID
size_t get_client_idx(upd_chatroom *chatroom, const char *uid) {
    if (!uid) return -1;

    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients);

        if (ctx->conn_bind_uid && strcmp(ctx->conn_bind_uid, uid) == 0) {
            return i;
        }
    }
    return -1; // Client not found
}
