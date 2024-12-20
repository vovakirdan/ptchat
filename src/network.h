#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <netdb.h>
#include "user.h"
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
 * @return An initialized `conn_ctx`.
 */
conn_ctx conn_ctx_init(struct sockaddr_in conn_addr, char *conn_bind_uid, int conn_status);

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
    user_database *user_db;    // User database
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

/**
 * @brief Check if the host name is valid.
 *
 * @param hostname The host name to check.
 */
void checkHostName(int hostname);

/**
 * @brief Check if the host entry is valid.
 *
 * @param hostentry The host entry to check.
 */
void checkHostEntry(struct hostent * hostentry);

/**
 * @brief Convert the host name to IP address.
 *
 * @param hostname The host name to convert.
 * @return The IP address of the host.
 */
void checkIPbuffer(char *IPbuffer);

/**
 * Broadcast a message to all connected clients.
 *
 * @param chatroom Pointer to the chatroom structure.
 * @param include_self Whether to include the sender in the broadcast.
 * @param sender_uid The UID of the sender (can be NULL for system messages).
 * @param message The message to broadcast.
 * @return The number of clients the message was successfully sent to.
 */
size_t system_broadcasting(upd_chatroom *chatroom, bool include_self, const char *sender_uid, const char *message);

/**
 * @brief Notifies a client of a reset condition and resets or clears their connection context.
 *
 * This function sends a message to the client to inform them of an error or reset condition.
 * It then either clears the client's connection context entirely or resets it to the main menu,
 * depending on the `clean_client` parameter.
 *
 * @param chatroom Pointer to the chatroom instance containing server and client information.
 * @param msg The message to send to the client.
 * @param ctx The client connection context to reset or clear.
 * @param clean_client If `true`, clears the client's context completely; if `false`, resets to the main menu.
 */
void notify_reset_conn(upd_chatroom *chatroom, const char *msg, conn_ctx *ctx, bool clean_client);

/**
 * @brief Converts a client's socket address into a string message.
 *
 * This function takes a `struct sockaddr_in` representing a client's address
 * and returns a dynamically allocated string containing the IP address and port
 * in the format "IP:Port\n".
 *
 * @param addr The client's socket address (`struct sockaddr_in`).
 * @return A dynamically allocated string with the address information. Caller must free.
 *         Returns `NULL` on failure.
 */
char *addr_to_msg(struct sockaddr_in addr);

#endif // NETWORK_H
