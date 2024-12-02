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
    if (chatroom->server_fd == -1) {
        fprintf(stderr, "Server not started.\n");
        return;
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char *buffer = malloc(chatroom->buff_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer.\n");
        return;
    }

    printf("Chat server is running...\n");

    // Define a bind buffer for handling re-sign in
    typedef struct {
        char *user_uid;
        size_t prev_ctx_idx;
        bool is_set;
    } ctx_user_bind_buffer;

    ctx_user_bind_buffer bind_buffer = {NULL, (size_t)-1, false};

    while (1) {
        memset(buffer, 0, chatroom->buff_size);

        // Receive a message from any client
        ssize_t received = recvfrom(chatroom->server_fd, buffer, chatroom->buff_size - 1, 0,
                                    (struct sockaddr *)&client_addr, &addr_len);

        if (received < 0) {
            perror("recvfrom failed");
            continue;
        }

        // Omit the '\n' char if any and null-terminate
        if (buffer[received - 1] == '\n') {
            buffer[received - 1] = '\0';
        } else {
            buffer[received] = '\0';
        }

        printf("Received %zd bytes from %s:%d: %s\n", received,
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);

        size_t conn_idx = get_conn_idx(chatroom, client_addr);

        // New connection, initialize it.
        if (conn_idx == (size_t)-1) {
            conn_ctx new_conn = conn_ctx_init(client_addr, NULL, 1); // Status 1: Main menu
            vector__push_back(conn_ctx, new_conn, chatroom->clients);

            const char *main_menu = "1. Sign up\n2. Sign in\nPlease choose (1 | 2): ";
            simple_send(chatroom, main_menu, strlen(main_menu), client_addr);

            printf("New client connected: %s:%d\n",
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            continue;
        }

        // conn_idx is valid. Start processing.
        conn_ctx *client_ctx = vector__access(conn_ctx, conn_idx, chatroom->clients);
        int stat = client_ctx->conn_status;
        char *buff_str = buffer; // Use buffer as a string

        if (stat == 0) {
            const char *main_menu = "1. Sign up\n2. Sign in\nPlease choose (1 | 2): ";
            simple_send(chatroom, main_menu, strlen(main_menu), client_addr);
            client_ctx->conn_status = 1;
            continue;
        }

        if (stat == 100) { // Waiting for yes or no
            if (strcmp(buff_str, "yes") != 0 && strcmp(buff_str, "no") != 0) {
                const char *not_yes_or_no = "Option error, please send either yes or no.\n";
                notify_reset_conn(chatroom, not_yes_or_no, client_ctx, false);
                continue;
            }
            if (strcmp(buff_str, "yes") == 0) {
                const char *input_password = "Password: ";
                simple_send(chatroom, input_password, strlen(input_password), client_addr);

                const char *another_sign_warn = "[SYSTEM_WARN] Another client is trying to sign in your UID!\n";
                // Notify previous client
                if (bind_buffer.prev_ctx_idx != (size_t)-1) {
                    conn_ctx *prev_client_ctx = vector__access(conn_ctx, bind_buffer.prev_ctx_idx, chatroom->clients);
                    simple_send(chatroom, another_sign_warn, strlen(another_sign_warn), prev_client_ctx->conn_addr);
                }

                // Update current client context
                if (bind_buffer.user_uid) {
                    if (client_ctx->conn_bind_uid) free(client_ctx->conn_bind_uid);
                    client_ctx->conn_bind_uid = strdup(bind_buffer.user_uid);
                }
                client_ctx->conn_status = 5;
            } else {
                const char *option_denied = "You sent no. Nothing changed.\n";
                notify_reset_conn(chatroom, option_denied, client_ctx, false);
            }
            continue;
        }

        if (stat == 1) {
            if (strcmp(buff_str, "1") != 0 && strcmp(buff_str, "2") != 0) {
                const char *option_error = "Option error, please input 1 or 2\n";
                notify_reset_conn(chatroom, option_error, client_ctx, false);
                continue;
            }
            if (strcmp(buff_str, "1") == 0) {
                const char *input_username = "Username: ";
                simple_send(chatroom, input_username, strlen(input_username), client_addr);
                client_ctx->conn_status = 2; // Sign up
            } else {
                const char *input_username = "Username: ";
                simple_send(chatroom, input_username, strlen(input_username), client_addr);
                client_ctx->conn_status = 3; // Sign in
            }
            continue;
        }

        if (stat == 2 || stat == 3) {
            // User provided username
            int flag = user_uid_check(buff_str);
            if (flag == -1) {
                const char *invalid_uid_len = "Invalid UID length: 4-64\n";
                notify_reset_conn(chatroom, invalid_uid_len, client_ctx, false);
                continue;
            }
            if (flag == 1) {
                const char *invalid_uid_fmt = "Invalid UID format, rules to follow:\n4-64 ASCII chars.\nLetters, numbers, and hyphen '-'.\n";
                notify_reset_conn(chatroom, invalid_uid_fmt, client_ctx, false);
                continue;
            }
            if (stat == 2) {
                // Sign up
                if (user_db_contains(chatroom->user_db, buff_str)) {
                    const char *user_uid_exist = "User already exists.\n";
                    notify_reset_conn(chatroom, user_uid_exist, client_ctx, false);
                    continue;
                }
                const char *input_password = "Password: ";
                simple_send(chatroom, input_password, strlen(input_password), client_addr);
                if (client_ctx->conn_bind_uid) free(client_ctx->conn_bind_uid);
                client_ctx->conn_bind_uid = strdup(buff_str);
                client_ctx->conn_status = 4;
                continue;
            }
            if (!user_db_contains(chatroom->user_db, buff_str)) {
                const char *user_uid_error = "User does not exist.\n";
                notify_reset_conn(chatroom, user_uid_error, client_ctx, false);
                continue;
            }
            size_t client_idx = get_client_idx(chatroom, buff_str);
            if (client_idx != (size_t)-1) {
                const char *user_already_signin = "User already signed in at another client.\n";
                simple_send(chatroom, user_already_signin, strlen(user_already_signin), client_addr);
                char *addr_msg = addr_to_msg(vector__access(conn_ctx, client_idx, chatroom->clients)->conn_addr);
                simple_send(chatroom, addr_msg, strlen(addr_msg), client_addr);
                free(addr_msg);
                const char *user_resign_in = "This sign-in would quit that client, are you sure? (yes | no)\n";
                simple_send(chatroom, user_resign_in, strlen(user_resign_in), client_addr);
                if (bind_buffer.user_uid) free(bind_buffer.user_uid);
                bind_buffer.user_uid = strdup(buff_str);
                bind_buffer.prev_ctx_idx = client_idx;
                bind_buffer.is_set = true;
                client_ctx->conn_status = 100;
                continue;
            }
            const char *input_password = "Password: ";
            simple_send(chatroom, input_password, strlen(input_password), client_addr);
            if (client_ctx->conn_bind_uid) free(client_ctx->conn_bind_uid);
            client_ctx->conn_bind_uid = strdup(buff_str);
            client_ctx->conn_status = 5;
            continue;
        }

        if (stat == 4 || stat == 5) {
            // User provided password
            char *user_uid = client_ctx->conn_bind_uid;
            int flag = pass_str_check(buff_str);
            if (stat == 4) {
                // Sign up
                if (flag == -1) {
                    const char *invalid_pass_len = "Invalid password length: 8-64\n";
                    notify_reset_conn(chatroom, invalid_pass_len, client_ctx, false);
                    continue;
                }
                if (flag == 1) {
                    const char *invalid_pass_fmt = "Invalid password format, rules to follow:\n"
                                                "8-64 ASCII characters.\n"
                                                "Letters, numbers, and special characters.\n";
                    notify_reset_conn(chatroom, invalid_pass_fmt, client_ctx, false);
                    continue;
                }
                if (flag == 2) {
                    const char *password_not_complex = "The password is not complex enough.\n";
                    notify_reset_conn(chatroom, password_not_complex, client_ctx, false);
                    continue;
                }
                // Proceed to add the user
                if (!user_db_add(chatroom->user_db, user_uid, buff_str)) {
                    const char *signup_fail = "Failed to sign up. Try again.\n";
                    notify_reset_conn(chatroom, signup_fail, client_ctx, false);
                    continue;
                }
                user_db_set_status(chatroom->user_db, user_uid, 1);
                char *user_list = user_db_get_list(chatroom->user_db, true);
                const char *signup_ok = "Sign-up successful! You are now logged in.\n";
                simple_send(chatroom, signup_ok, strlen(signup_ok), client_addr);
                simple_send(chatroom, user_list, strlen(user_list), client_addr);
                free(user_list);

                char msg_body[256];
                snprintf(msg_body, sizeof(msg_body), " signed up and in!\n\n");
                system_broadcasting(chatroom, false, user_uid, msg_body);

                client_ctx->conn_status = 6;
                continue;
            }
            if (flag != 0) {
                const char *invalid_pass = "Not a valid password string.\n";
                notify_reset_conn(chatroom, invalid_pass, client_ctx, false);
                continue;
            }
            if (!user_db_validate_password(chatroom->user_db, user_uid, buff_str)) {
                const char *password_error = "Password doesn't match.\n";
                notify_reset_conn(chatroom, password_error, client_ctx, false);
                continue;
            }
            user_db_set_status(chatroom->user_db, user_uid, 1);
            char *user_list = user_db_get_list(chatroom->user_db, true);
            const char *signin_ok = "Sign-in successful! You are now logged in.\n";
            simple_send(chatroom, signin_ok, strlen(signin_ok), client_addr);
            simple_send(chatroom, user_list, strlen(user_list), client_addr);
            free(user_list);

            char msg_body[256];
            snprintf(msg_body, sizeof(msg_body), " signed in!\n\n");
            system_broadcasting(chatroom, false, user_uid, msg_body);

            if (bind_buffer.is_set) {
                conn_ctx *prev_client_ctx = vector__access(conn_ctx, bind_buffer.prev_ctx_idx, chatroom->clients);
                const char *client_switched = "You've re-signed in on another client. Signed out here.\n";
                notify_reset_conn(chatroom, client_switched, prev_client_ctx, true);
                // Clean up bind buffer
                if (bind_buffer.user_uid) free(bind_buffer.user_uid);
                bind_buffer.user_uid = NULL;
                bind_buffer.prev_ctx_idx = (size_t)-1;
                bind_buffer.is_set = false;
            }

            client_ctx->conn_status = 6;
            continue;
        }

        // User is logged in (status 6)
        char *user_uid = client_ctx->conn_bind_uid;
        if (strcmp(buff_str, "~:q!") == 0) {
            const char *signed_out = "[SYSTEM] You have signed out.\n";
            notify_reset_conn(chatroom, signed_out, client_ctx, true);

            char msg_body[256];
            snprintf(msg_body, sizeof(msg_body), " signed out!\n\n");
            system_broadcasting(chatroom, false, user_uid, msg_body);

            user_db_set_status(chatroom->user_db, user_uid, 0);
            continue;
        }

        if (strcmp(buff_str, "~:lu") == 0) {
            char *user_list = user_db_get_list(chatroom->user_db, true);
            simple_send(chatroom, user_list, strlen(user_list), client_addr);
            free(user_list);
            continue;
        }

        if (strlen(buff_str) == 0) {
            continue; // Skip empty messages
        }

        // Process message
        msg_attr *attr = msg_attr_init();
        int check = msg_precheck(buff_str, attr);
        if (check == 1) {
            const char *cannot_at_or_to_user = "[SYSTEM] Target user not signed in.\n";
            simple_send(chatroom, cannot_at_or_to_user, strlen(cannot_at_or_to_user), client_addr);
            msg_attr_free(attr);
            continue;
        }
        if (check == -1) {
            const char *cannot_at_or_to_self = "[SYSTEM] You cannot tag or send private messages to yourself.\n";
            simple_send(chatroom, cannot_at_or_to_self, strlen(cannot_at_or_to_self), client_addr);
            msg_attr_free(attr);
            continue;
        }

        // Prepare message buffer
        struct vector(char) msg_buffer = vector__create(char);
        // Copy the message into msg_buffer
        for (size_t i = 0; i < strlen(buff_str); i++) {
            vector__push_back(char, buff_str[i], msg_buffer);
        }

        if (!update_msg_buffer(&msg_buffer, attr, client_ctx)) {
            const char *internal_bug = "Internal error, probably a bug. Please report to us.\n";
            system_broadcasting(chatroom, true, "[ALL]", internal_bug);
            vector__destroy(char, NULL, msg_buffer);
            msg_attr_free(attr);
            continue;
        }

        if (attr->msg_type == MSG_PUBLIC) {
            // Broadcast to all clients
            for (size_t i = 0; i < chatroom->clients.size; i++) {
                conn_ctx *other_client = vector__access(conn_ctx, i, chatroom->clients);
                if (other_client->conn_status == 6) {
                    simple_send(chatroom, vector__begin(char, msg_buffer), msg_buffer.size, other_client->conn_addr);
                }
            }
        } else if (attr->msg_type == MSG_TAGGED) {
            // Broadcast to all, notify the tagged user
            for (size_t i = 0; i < chatroom->clients.size; i++) {
                conn_ctx *other_client = vector__access(conn_ctx, i, chatroom->clients);
                if (other_client->conn_status == 6) {
                    if (strcmp(other_client->conn_bind_uid, attr->target_uid) == 0) {
                        const char *been_tagged = "[SYSTEM_NOTIFY] You've been tagged!\n";
                        simple_send(chatroom, been_tagged, strlen(been_tagged), other_client->conn_addr);
                    }
                    simple_send(chatroom, vector__begin(char, msg_buffer), msg_buffer.size, other_client->conn_addr);
                }
            }
        } else if (attr->msg_type == MSG_PRIVATE) {
            // Send to target user only
            simple_send(chatroom, vector__begin(char, msg_buffer), msg_buffer.size, client_ctx->conn_addr);
            size_t target_idx = get_client_idx(chatroom, attr->target_uid);
            if (target_idx != (size_t)-1) {
                conn_ctx *target_client = vector__access(conn_ctx, target_idx, chatroom->clients);
                const char *private_msg_recved = "[SYSTEM_NOTIFY] You've received a private message!\n";
                simple_send(chatroom, private_msg_recved, strlen(private_msg_recved), target_client->conn_addr);
                simple_send(chatroom, vector__begin(char, msg_buffer), msg_buffer.size, target_client->conn_addr);
            } else {
                const char *cannot_at_or_to_user = "[SYSTEM] Target user not signed in.\n";
                simple_send(chatroom, cannot_at_or_to_user, strlen(cannot_at_or_to_user), client_ctx->conn_addr);
            }
        }

        // Clean up
        vector__destroy(char, NULL, msg_buffer);
        msg_attr_free(attr);
    }

    free(buffer);
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
