#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include "network.h"

conn_ctx conn_ctx_init(struct sockaddr_in conn_addr, char *conn_bind_uid, int conn_status) {
    conn_ctx ctx;
    ctx.conn_addr = conn_addr;
    ctx.conn_bind_uid = conn_bind_uid ? strdup(conn_bind_uid) : NULL;
    ctx.conn_status = conn_status;
    return ctx;
}

void conn_ctx_free(conn_ctx *ctx) {
    if (!ctx) return;
    free(ctx->conn_bind_uid);
    // free(ctx); // Do not free ctx itself, as it is not dynamically allocated.
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

    // Initialize user database
    chatroom->user_db = user_db_init();
    if (!chatroom->user_db) {
        fprintf(stderr, "Error initializing user database.\n");
        close(chatroom->server_fd);
        free(chatroom);
        return NULL;
    }

    // Bind socket
    if (bind(chatroom->server_fd, (struct sockaddr *)&chatroom->address, sizeof(chatroom->address)) < 0) {
        perror("Error binding socket");
        close(chatroom->server_fd);
        free(chatroom);
        return NULL;
    }

    // // set non-blocking mode
    // if (fcntl(chatroom->server_fd, F_SETFL, O_NONBLOCK) < 0) {
    //     perror("Failed to set non-blocking mode");
    //     close(chatroom->server_fd);
    //     free(chatroom);
    //     return NULL;
    // }

    chatroom->clients = vector__create(conn_ctx);
    // maybe we need to reserve?
    vector__reserve(conn_ctx, 32, chatroom->clients);

    char host[256];
    gethostname(host, sizeof(host));
    printf("Chat server started on %s :%d\n", host, ntohs(chatroom->address.sin_port));

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

    // Free the user database
    user_db_free(chatroom->user_db);

    free(chatroom);
}

int simple_send(upd_chatroom *chatroom, const void *buff, size_t n, struct sockaddr_in client_addr) {
    return sendto(chatroom->server_fd, buff, n, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
}

// Find the index of a connection by client address
size_t get_conn_idx(upd_chatroom *chatroom, struct sockaddr_in client_addr) {
    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients);

        if (ctx->conn_addr.sin_addr.s_addr == client_addr.sin_addr.s_addr) {
            return i;
        }
    }
    return (size_t)-1; // Client not found
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

void GetMachineName(char machineName[150]) {
    char Name[150];
    int i=0;

    #ifdef WIN32
        TCHAR infoBuf[150];
        DWORD bufCharCount = 150;
        memset(Name, 0, 150);
        if( GetComputerName( infoBuf, &bufCharCount ) )
        {
            for(i=0; i<150; i++)
            {
                Name[i] = infoBuf[i];
            }
        }
        else
        {
            strcpy(Name, "Unknown_Host_Name");
        }
    #else
        memset(Name, 0, 150);
        gethostname(Name, 150);
    #endif
    strncpy(machineName, Name, 150);
}

// Returns hostname for the local computer
void checkHostName(int hostname)
{
    if (hostname == -1)
    {
        perror("gethostname");
        exit(1);
    }
}

// Returns host information corresponding to host name
void checkHostEntry(struct hostent * hostentry)
{
    if (hostentry == NULL)
    {
        perror("gethostbyname");
        exit(1);
    }
}

// Converts space-delimited IPv4 addresses
// to dotted-decimal format
void checkIPbuffer(char *IPbuffer)
{
    if (NULL == IPbuffer)
    {
        perror("inet_ntoa");
        exit(1);
    }
}

size_t system_broadcasting(upd_chatroom *chatroom, bool include_self, const char *sender_uid, const char *message) {
    if (!chatroom || !message) return 0;

    char broadcast_msg[1024];
    size_t sent_count = 0;

    // Format the broadcast message
    if (sender_uid) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "[%s]: %s", sender_uid, message);
    } else {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "[SYSTEM]: %s", message);
    }

    // Iterate over all connected clients
    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *client = vector__access(conn_ctx, i, chatroom->clients);

        if (client->conn_status == 3) { // Only send to authenticated clients
            if (!include_self && sender_uid && strcmp(client->conn_bind_uid, sender_uid) == 0) {
                continue; // Skip the sender if include_self is false
            }

            if (simple_send(chatroom, broadcast_msg, strlen(broadcast_msg), client->conn_addr) >= 0) {
                sent_count++;
            } else {
                perror("Broadcast message failed");
            }
        }
    }

    return sent_count;
}

void notify_reset_conn(upd_chatroom *chatroom, const char *msg, conn_ctx *ctx, bool clean_client) {
    if (!chatroom || !ctx || !msg) return;

    // Send the message to the client
    simple_send(chatroom, msg, strlen(msg), ctx->conn_addr);

    // Send the connection reset message
    const char *connection_reset = "This connection has been reset.\n\n";
    simple_send(chatroom, connection_reset, strlen(connection_reset), ctx->conn_addr);

    if (clean_client) {
        // Clear the client context completely
        clear_conn(ctx);
    } else {
        // Send the main menu again
        const char *main_menu = "1. Sign up\n2. Sign in\nPlease choose (1 | 2): ";
        simple_send(chatroom, main_menu, strlen(main_menu), ctx->conn_addr);
        ctx->conn_status = 1; // Reset to main menu status
    }
}

char *addr_to_msg(struct sockaddr_in addr) {
    char ip_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &(addr.sin_addr), ip_str, sizeof(ip_str))) {
        perror("inet_ntop failed");
        return NULL;
    }
    size_t msg_len = INET_ADDRSTRLEN + 8; // Enough space for IP, colon, port, newline, and null terminator
    char *msg = malloc(msg_len);
    if (!msg) {
        fprintf(stderr, "Memory allocation failed in addr_to_msg\n");
        return NULL;
    }
    snprintf(msg, msg_len, "%s:%d\n", ip_str, ntohs(addr.sin_port));
    return msg;
}