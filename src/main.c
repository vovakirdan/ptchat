#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "network.h"
#include "user.h"
#include "message.h"
#include "utils.h"

#define DEFAULT_PORT 8081
#define INIT_BUFF_SIZE 4096

// Global server instance
upd_chatroom *server = NULL;

// Signal handler for graceful shutdown
void handle_signal(int signal) {
    if (server) {
        printf("\nShutting down server...\n");
        upd_chatroom_free(server);
    }
    exit(0);
}

// Main server loop
void run_server(upd_chatroom *chatroom) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[INIT_BUFF_SIZE];

    while (1) {
        memset(buffer, 0, INIT_BUFF_SIZE);
        ssize_t received = recvfrom(chatroom->server_fd, buffer, INIT_BUFF_SIZE - 1, 0,
                                    (struct sockaddr *)&client_addr, &addr_len);

        if (received < 0) {
            perror("Error receiving data");
            continue;
        }

        buffer[received] = '\0'; // Null-terminate the buffer

        printf("Received message from %s:%d -> %s\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);

        // Check if this is a new connection
        size_t conn_idx = get_conn_idx(chatroom, client_addr);
        if (conn_idx == -1) {
            // New client connection
            conn_ctx *new_client = conn_ctx_init(client_addr, NULL, 0);
            vector__push_back(conn_ctx, *new_client, chatroom->clients);

            const char *welcome_msg = "Welcome to the chat server!\n";
            simple_send(chatroom, welcome_msg, strlen(welcome_msg), client_addr);
            continue;
        }

        // Existing client processing
        conn_ctx *client_ctx = vector__access(conn_ctx, conn_idx, chatroom->clients);

        // Process the received message
        if (strcmp(buffer, "~:q!") == 0) {
            // Handle user sign-out
            if (client_ctx->conn_bind_uid) {
                user_db_set_status(&chatroom->user_db, client_ctx->conn_bind_uid, 0);
            }
            simple_send(chatroom, "You have signed out.\n", 21, client_addr);
            clear_conn(client_ctx);
            continue;
        }

        if (strcmp(buffer, "~:lu") == 0) {
            // Send user list
            char *user_list = user_db_get_list(&chatroom->user_db, true);
            simple_send(chatroom, user_list, strlen(user_list), client_addr);
            free(user_list);
            continue;
        }

        // Message precheck for attributes
        msg_attr attr;
        msg_precheck(buffer, &attr);

        if (attr.msg_type == MSG_PRIVATE && attr.target_uid) {
            // Send private message
            size_t target_idx = get_client_idx(chatroom, attr.target_uid);
            if (target_idx != -1) {
                conn_ctx *target_ctx = vector__access(conn_ctx, target_idx, chatroom->clients);
                simple_send(chatroom, buffer, strlen(buffer), target_ctx->conn_addr);
            } else {
                simple_send(chatroom, "Target user not online.\n", 25, client_addr);
            }
        } else if (attr.msg_type == MSG_TAGGED && attr.target_uid) {
            // Handle tagged message
            size_t target_idx = get_client_idx(chatroom, attr.target_uid);
            if (target_idx != -1) {
                conn_ctx *target_ctx = vector__access(conn_ctx, target_idx, chatroom->clients);
                simple_send(chatroom, buffer, strlen(buffer), target_ctx->conn_addr);
            }
        } else {
            // Broadcast public message
            system_broadcast(chatroom, false, client_ctx->conn_bind_uid, buffer);
        }
    }
}

// Main entry point
int main(int argc, char *argv[]) {
    // Parse command-line arguments
    uint16_t port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    char hostbuffer[256];
    char *IPbuffer;
    struct hostent *host_entry;
    int hostname;

    // Set up signal handlers for graceful shutdown
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Initialize server
    server = upd_chatroom_init(port, INIT_BUFF_SIZE);
    if (!server) {
        fprintf(stderr, "Failed to initialize chatroom.\n");
        return EXIT_FAILURE;
    }

    // To retrieve hostname
    hostname = gethostname(hostbuffer, sizeof(hostbuffer));
    checkHostName(hostname);

    // To retrieve host information
    host_entry = gethostbyname(hostbuffer);
    checkHostEntry(host_entry);

    // To convert an Internet network
    // address into ASCII string
    IPbuffer = inet_ntoa(*((struct in_addr*)
                        host_entry->h_addr_list[0]));
    printf("Chat server started on %s %s:%d.\n", hostbuffer, IPbuffer, port);

    // Run the server
    run_server(server);

    // Cleanup (in case of unexpected exit)
    upd_chatroom_free(server);
    return EXIT_SUCCESS;
}
