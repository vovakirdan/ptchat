#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
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
    char buffer[chatroom->buff_size];

    printf("Chat server is running...\n");

    while (1) {
        memset(buffer, 0, chatroom->buff_size);

        // Receive a message from any client
        ssize_t received = recvfrom(chatroom->server_fd, buffer, chatroom->buff_size - 1, MSG_WAITALL,
                                    (struct sockaddr *)&client_addr, &addr_len);

        if (received < 0) {
            perror("recvfrom failed");
            continue;
        }

        buffer[received] = '\0'; // Null-terminate the received data
        printf("Received %zd bytes from %s:%d. Message: %s\n", received,
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);

        // Echo the message back to the client
        // if (simple_send(chatroom, buffer, received, client_addr) < 0) {
        //     perror("Error sending response");
        // }

        // Check if this is a new connection
        size_t conn_idx = get_conn_idx(chatroom, client_addr);
        printf("conn_idx %zu\n", conn_idx);
        if (conn_idx == (size_t)-1) {
            // New client connection
            conn_ctx new_client = conn_ctx_init(client_addr, NULL, 0); // Unbound, waiting for username
            vector__push_back(conn_ctx, new_client, chatroom->clients);

            const char *welcome_msg = "Welcome to the chat server! Please log in or sign up.\n";
            simple_send(chatroom, welcome_msg, strlen(welcome_msg), client_addr);

            printf("New client connected: %s:%d\n",
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            continue;
        }

        // Existing client processing
        conn_ctx *client_ctx = vector__access(conn_ctx, conn_idx, chatroom->clients);
        // printf("Received message from client %s:%d: %s\n",
        //        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);
        printf("connection status: %d\n", client_ctx->conn_status);
        if (client_ctx->conn_status == 0) {
            // Client needs to provide a username
            if (user_db_contains(chatroom->user_db, buffer)) {
                // Username exists, prompt for password
                client_ctx->conn_bind_uid = strdup(buffer);
                client_ctx->conn_status = 1; // Awaiting password

                const char *password_prompt = "Password: ";
                simple_send(chatroom, password_prompt, strlen(password_prompt), client_addr);
            } else {
                // Username doesn't exist, create new user
                client_ctx->conn_bind_uid = strdup(buffer);
                client_ctx->conn_status = 2; // Awaiting password for new user

                const char *signup_prompt = "New user! Please provide a password to sign up: ";
                simple_send(chatroom, signup_prompt, strlen(signup_prompt), client_addr);
            }
            continue;
        }

        if (client_ctx->conn_status == 1 || client_ctx->conn_status == 2) {
            // Handle password entry
            if (client_ctx->conn_status == 1) {
                // Authenticate existing user
                if (user_db_validate_password(chatroom->user_db, client_ctx->conn_bind_uid, buffer)) {
                    client_ctx->conn_status = 3; // Authenticated
                    user_db_set_status(chatroom->user_db, client_ctx->conn_bind_uid, 1);

                    const char *login_success = "Logged in successfully!\n";
                    simple_send(chatroom, login_success, strlen(login_success), client_addr);

                    char *user_list = user_db_get_list(chatroom->user_db, true);
                    simple_send(chatroom, user_list, strlen(user_list), client_addr);
                    free(user_list);
                } else {
                    const char *auth_fail = "Incorrect password. Try again.\n";
                    simple_send(chatroom, auth_fail, strlen(auth_fail), client_addr);
                }
            } else if (client_ctx->conn_status == 2) {
                // Register new user
                if (user_db_add(chatroom->user_db, client_ctx->conn_bind_uid, buffer)) {
                    client_ctx->conn_status = 3; // Authenticated
                    user_db_set_status(chatroom->user_db, client_ctx->conn_bind_uid, 1);

                    const char *signup_success = "Sign-up successful! You are now logged in.\n";
                    simple_send(chatroom, signup_success, strlen(signup_success), client_addr);

                    char *user_list = user_db_get_list(chatroom->user_db, true);
                    simple_send(chatroom, user_list, strlen(user_list), client_addr);
                    free(user_list);
                } else {
                    const char *signup_fail = "Failed to sign up. Try again.\n";
                    simple_send(chatroom, signup_fail, strlen(signup_fail), client_addr);
                }
            }
            continue;
        }

        // Authenticated client: Process chat messages
        if (client_ctx->conn_status == 3) {
            if (strcmp(buffer, "~:q!") == 0) {
                // Handle sign-out
                user_db_set_status(chatroom->user_db, client_ctx->conn_bind_uid, 0);
                clear_conn(client_ctx);

                const char *logout_msg = "You have signed out.\n";
                simple_send(chatroom, logout_msg, strlen(logout_msg), client_addr);

                char broadcast_msg[256];
                snprintf(broadcast_msg, sizeof(broadcast_msg), "[SYSTEM] %s has signed out.\n", client_ctx->conn_bind_uid);
                system_broadcasting(chatroom, false, client_ctx->conn_bind_uid, broadcast_msg);
                continue;
            }

            // Broadcast message to other clients
            char broadcast_msg[512];
            snprintf(broadcast_msg, sizeof(broadcast_msg), "[%s]: %s\n", client_ctx->conn_bind_uid, buffer);
            system_broadcasting(chatroom, true, client_ctx->conn_bind_uid, broadcast_msg);
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
    // printf("Script get started on %s %s:%d.\n", hostbuffer, IPbuffer, port);

    // Run the server
    run_server(server);

    // Cleanup (in case of unexpected exit)
    upd_chatroom_free(server);
    return EXIT_SUCCESS;
}
