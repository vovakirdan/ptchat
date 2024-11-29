#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include "../cbinc/vector.h"
#include "../cbinc/dict.h"

// Connection Context: Represents a single client's connection state
typedef struct {
    struct sockaddr_in conn_addr;  // Connection address
    char *conn_bind_uid;           // Bound user UID
    int conn_status;               // Connection status
} conn_ctx;

/**
 * @brief Initializes a connection context.
 *
 * @param conn_addr The address of the connection.
 * @param conn_bind_uid The bound user UID (can be NULL initially).
 * @param conn_status The initial status of the connection.
 * @return A pointer to the initialized `conn_ctx`. Caller must free.
 */
conn_ctx *conn_ctx_init(struct sockaddr_in conn_addr, char *conn_bind_uid, int conn_status);

/**
 * @brief Frees a connection context.
 *
 * @param ctx The connection context to free.
 */
void conn_ctx_free(conn_ctx *ctx);

// Chatroom: Manages the server state and connected clients
typedef struct {
    struct sockaddr_in address;         // Server address
    uint16_t port;                      // Server port
    int server_fd;                      // Server socket file descriptor
    size_t buff_size;                   // Buffer size for I/O
    int err_code;                       // Error code for server state
    struct dict(user_entry) user_db;    // User database
    struct vector(conn_ctx) clients;    // List of connected clients
} upd_chatroom;

/**
 * @brief Initializes a chatroom.
 *
 * @param port The port to bind the server to.
 * @param buff_size The buffer size for handling messages.
 * @return A pointer to the initialized `upd_chatroom`. Caller must free.
 */
upd_chatroom *upd_chatroom_init(uint16_t port, size_t buff_size);

/**
 * @brief Frees a chatroom.
 *
 * @param chatroom The chatroom to free.
 */
void upd_chatroom_free(upd_chatroom *chatroom);

/**
 * @brief Sends a message to a specific client.
 *
 * @param chatroom The chatroom managing the server.
 * @param buff The message buffer to send.
 * @param n The size of the message buffer.
 * @param client_addr The target client's address.
 * @return The result of the `sendto` call.
 */
int simple_send(upd_chatroom *chatroom, const void *buff, size_t n, struct sockaddr_in client_addr);

/**
 * @brief Gets the index of a client in the chatroom's clients list based on the address.
 *
 * @param chatroom The chatroom containing the client list.
 * @param client_addr The address of the client to find.
 * @return The index of the client in the `clients` vector, or -1 if not found.
 */
size_t get_conn_idx(upd_chatroom *chatroom, struct sockaddr_in client_addr);

/**
 * @brief Clears the state of a connection context.
 *
 * @param ctx The connection context to clear.
 */
void clear_conn(conn_ctx *ctx);

/**
 * @brief Gets the index of a client based on its bound UID.
 *
 * @param chatroom The chatroom containing the client list.
 * @param uid The unique ID of the client to find.
 * @return The index of the client in the `clients` vector, or -1 if not found.
 */
size_t get_client_idx(upd_chatroom *chatroom, const char *uid);

#endif // NETWORK_H
