#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "cbinc/vector.h"
#include "cbinc/dict.h"
#include "main.h"
// https://github.com/zhenrong-wang/lichat/tree/main involved

// Each user entry include a unique id and a hashed password
// This approach is not secure enough because we just used ordinary 
// SHA-256 to hash the password.
typedef struct {
    char *user_uid;  // unique ID
    char *pass_hash;  // hashed password
    uint8_t user_status;  // 0 - not online, 1 - online
} user_entry;

typedef struct {
    char *user_uid;
    size_t ctx_idx_prev;
    bool is_set;
} ctx_user_bind_buffer;

// ctx_user_bind_buffer construnctor
ctx_user_bind_buffer *ctx_user_bind_buffer_init(char *user_uid, size_t ctx_idx_prev, bool is_set) {
    ctx_user_bind_buffer *ctx_user_bind_buf = malloc(sizeof(ctx_user_bind_buffer));
    if (ctx_user_bind_buf == NULL) {
        fprintf(stderr, "malloc for ctx_user_bind_buffer failed\n");
        exit(EXIT_FAILURE);
    }
    ctx_user_bind_buf->user_uid = user_uid;
    ctx_user_bind_buf->ctx_idx_prev = ctx_idx_prev;
    ctx_user_bind_buf->is_set = is_set;
    return ctx_user_bind_buf;
}

// ctx_user_bind_buffer destructor
void ctx_user_bind_buffer_free(ctx_user_bind_buffer *ctx_user_bind_buf) {
    free(ctx_user_bind_buf->user_uid);
    free(ctx_user_bind_buf);
}

void set_bind_buffer(ctx_user_bind_buffer *ctx_user_bind_buf, char* uid, size_t idx) {
    ctx_user_bind_buf->user_uid = uid;
    ctx_user_bind_buf->ctx_idx_prev = idx;
    ctx_user_bind_buf->is_set = true;
}

void unset_bind_buffer(ctx_user_bind_buffer *ctx_user_bind_buf) {
    ctx_user_bind_buf->user_uid = NULL;
    ctx_user_bind_buf->ctx_idx_prev = 0;
    ctx_user_bind_buf->is_set = false;
}
// no getters yet

typedef struct {
    uint8_t msg_attr_mask;  // 00 public & untagget; 01 public but tagged; 10 private
    char* target_uid;
    size_t target_ctx_idx;
    bool is_set;
} msg_attr;

// msg_attr constructor
msg_attr *msg_attr_init(uint8_t msg_attr_mask, char* target_uid, size_t target_ctx_idx, bool is_set) {
    msg_attr *msg_attr = malloc(sizeof(msg_attr));
    if (msg_attr == NULL) {
        fprintf(stderr, "malloc for msg_attr failed\n");
        exit(EXIT_FAILURE);
    }
    msg_attr->msg_attr_mask = msg_attr_mask;
    msg_attr->target_uid = target_uid;
    msg_attr->target_ctx_idx = target_ctx_idx;
    msg_attr->is_set = is_set;
    return msg_attr;
}

// msg_attr destructor
void msg_attr_free(msg_attr *msg_attr) {
    free(msg_attr->target_uid);
    free(msg_attr);
}

// Connection Context contains an addr, a bind/empty uid and a status
typedef struct {
    struct sockaddr_in conn_addr;  // connection addr info
    char* conn_bind_uid;  // binded/empty user unique ID
    int conn_status;  // connection status
} conn_ctx;

// Connection Context constructor
conn_ctx *conn_ctx_init(struct sockaddr_in conn_addr, char* conn_bind_uid, int conn_status) {
    conn_ctx *ctx = malloc(sizeof(conn_ctx));
    if (ctx == NULL) {
        fprintf(stderr, "malloc for conn_ctx failed\n");
        exit(EXIT_FAILURE);
    }
    ctx->conn_addr = conn_addr;
    ctx->conn_bind_uid = conn_bind_uid;
    ctx->conn_status = conn_status;
    return ctx;
}

// Connection Context destructor
void conn_ctx_free(conn_ctx *ctx) {
    free(ctx->conn_bind_uid);
    free(ctx);
}

const struct sockaddr_in *get_conn_addr(conn_ctx *ctx) {
    return &ctx->conn_addr;
}

void set_conn_addr(conn_ctx *ctx, struct sockaddr_in conn_addr) {
    ctx->conn_addr = conn_addr;
}

void set_conn_bind_uid(conn_ctx *ctx, char* conn_bind_uid) {
    ctx->conn_bind_uid = conn_bind_uid;
}

void set_conn_status(conn_ctx *ctx, int conn_status) {
    ctx->conn_status = conn_status;
}
// no getters yet

void reset_conn(conn_ctx *ctx) {
    ctx->conn_bind_uid = NULL;
    ctx->conn_status = 1;
}

void clear_conn(conn_ctx *ctx) {
    ctx->conn_addr = (struct sockaddr_in){0};
    ctx->conn_bind_uid = NULL;
    ctx->conn_status = 0;
}

// The user storage is in memory, no persistence.
// todo consider using a databse
typedef struct {
    struct dict(user_entry) user_db;
    char* user_list_fmt;
} user_database;

// User Database constructor
user_database *user_db_init(struct dict(user_entry) user_db, char* user_list_fmt) {
    user_database *db = malloc(sizeof(user_database));
    if (db == NULL) {
        fprintf(stderr, "malloc for user_database failed\n");
        exit(EXIT_FAILURE);
    }
    db->user_db = user_db;
    db->user_list_fmt = user_list_fmt;
    return db;
}

// User Database destructor
void user_db_free(user_database *db) {
    free(db->user_list_fmt);
    dict_free(&db->user_db);
    free(db);
}

static char* get_pass_hash(char *password) {
    // Ensure the password is not NULL
    if (!password) {
        return NULL;
    }

    // Allocate memory for the salt
    unsigned char salt[SALT_LENGTH];
    if (!RAND_bytes(salt, SALT_LENGTH)) {
        fprintf(stderr, "Error generating random salt.\n");
        return NULL;
    }

    // Allocate memory for the hash output
    unsigned char hash[HASH_LENGTH];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           salt, SALT_LENGTH,
                           ITERATIONS, EVP_sha256(),
                           HASH_LENGTH, hash)) {
        fprintf(stderr, "Error computing PBKDF2 hash.\n");
        return NULL;
    }

    // Allocate memory for the result string (hex hash + salt + NULL terminator)
    size_t result_len = SALT_LENGTH * 2 + HASH_LENGTH * 2 + 2;
    char *result = malloc(result_len);
    if (!result) {
        fprintf(stderr, "Error allocating memory for hash result.\n");
        return NULL;
    }

    // Convert the salt to hexadecimal and prepend it to the result
    char *ptr = result;
    for (int i = 0; i < SALT_LENGTH; i++) {
        sprintf(ptr, "%02x", salt[i]);
        ptr += 2;
    }
    *ptr++ = ':';

    // Convert the hash to hexadecimal and append it to the result
    for (int i = 0; i < HASH_LENGTH; i++) {
        sprintf(ptr, "%02x", hash[i]);
        ptr += 2;
    }
    *ptr = '\0'; // Null-terminate the string

    // Clear the password in memory
    memset(password, 0, strlen(password));

    return result;
}

user_entry *get_user_entry(user_database *db, char *username) {
    const struct slice key = slice__create(char, username, strlen(username));
    user_entry *result = dict__search(user_entry, key, db->user_db);
    return result;
}

bool is_in_db(user_database *db, char *username) {
    return get_user_entry(db, username) != NULL;
}

size_t count_users(user_database *db) {
    return db->user_db.keys.size;
}

// only alphabet, numbers and hyphen are allowed in username. Length 4-64
static int user_uid_check(const char *username) {
    if (strlen(username) < 4 || strlen(username) > 64) {
        return -1;  // length error
    }
    for (int i = 0; i < strlen(username); i++) {
        if (!isalnum(username[i]) && username[i] != '-') {
            return 0;  // incompatible name error
        }
    }
    return 1;  // true
}

// only alphabet, numbers and hyphen are allowed in password. Length 8-64
static int pass_check(const char *password) {
    if (strlen(password) < 8 || strlen(password) > 64) {
        return -1;  // length error
    }
    uint8_t has_num = 0;
    uint8_t has_lower_char = 0;
    uint8_t has_special_char = 0;
    uint8_t has_upper_char = 0;
    for (int i = 0; i < strlen(password); i++) {
        if (isdigit(password[i])) {
            has_num = 1;
        } else if (islower(password[i])) {
            has_lower_char = 1;
        } else if (ispunct(password[i]) || isspace(password[i])) {
            has_special_char = 1;
        } else if (isupper(password[i])) {
            has_upper_char = 1;
        }
    }
    if (has_num && has_lower_char && has_special_char && has_upper_char) {
        return 1;  // true
    } else {
        return 0;  // false
    }
}

bool add_user(user_database *db, char *username, char *password) {
    if (!username || !password) return false;
    if (is_in_db(db, username)) {
        return false;
    }
    if (user_uid_check(username) != 1) {
        return false;
    }
    if (pass_check(password) != 1) {
        return false;
    }

    char *pass_hash = get_pass_hash(password);
    user_entry *user = user_entry_init(username, pass_hash);

    const struct slice key = slice__create(char, username, strlen(username));
    dict__insert(user_entry, key, *user, db->user_db);

    // add to user list
    db->user_list_fmt = realloc(db->user_list_fmt, strlen(db->user_list_fmt) + strlen(username) + 1);
    strcat(db->user_list_fmt, username);
    strcat(db->user_list_fmt, "\n");
    return true;
}

bool is_pass_valid(user_database *db, char *username, char *password) {
    if (!username || !password) return false;
    if (!is_in_db(db, username)) {
        return false;
    }
    user_entry *user = get_user_entry(db, username);
    if (!user) return false; // todo check it
    char *pass_hash = get_pass_hash(password);
    return strcmp(user->pass_hash, pass_hash) == 0;
}

char* get_user_list(user_database *db, bool show_status) {
    if (!show_status) return db->user_list_fmt;
    char *list_with_status;
    for (int i = 0; i < db->user_db.keys.size; i++) {
        char *username = (char*)vector__access(char*, i, db->user_db.keys.data);
        user_entry *user = get_user_entry(db, username);
        if (user->user_status == 1) {
            list_with_status = realloc(list_with_status, strlen(list_with_status) + strlen(username) + 2);
            strcat(list_with_status, username);
            strcat(list_with_status, ":online\n");
        } else {
            list_with_status = realloc(list_with_status, strlen(list_with_status) + strlen(username) + 2);
            strcat(list_with_status, username);
            strcat(list_with_status, ":offline\n");
        }
    }
    return list_with_status;
}

void set_user_status(user_database *db, char *username, int status) {
    user_entry *user = get_user_entry(db, username);
    if (!user) return; // todo check it
    user->user_status = status;
    // todo update user list (db->user)
}
//todo count online users


// the main struct
typedef struct {
    struct sockaddr_in address;  // socket addr
    uint16_t port;  // port number
    int server_fd;  // socket fd
    size_t buff_size;  // io buffer size
    int err_code;  // error code
    user_database *user_db;  // user database
    struct vector(conn_ctx) clients;  // clients
} upd_chatroom;

// chatroom constructor
upd_chatroom *upd_chatroom_init(uint16_t port, size_t buff_size) {
    upd_chatroom *chatroom = malloc(sizeof(upd_chatroom));
    chatroom->server_fd = -1;  // socket(AF_INET, SOCK_DGRAM, 0);
    chatroom->address.sin_family = AF_INET;
    chatroom->address.sin_addr.s_addr = INADDR_ANY;
    chatroom->address.sin_port = htons(port);
    chatroom->port = port;
    chatroom->buff_size = buff_size;
    chatroom->err_code = 0;
    vector__reserve_exact(conn_ctx, chatroom->buff_size, chatroom->clients);
    chatroom->clients = vector__create(conn_ctx);
    // chatroom->user_db = user_database_init()  // idk if it needed
    return chatroom;
}

// chatroom destructor
void upd_chatroom_free(upd_chatroom *chatroom) {  // todo maybe not full
    free(chatroom);
    user_db_free(chatroom->user_db);
    vector__destroy(conn_ctx, NULL, chatroom->clients);
}

// Close server and possible FD
bool close_server(upd_chatroom *chatroom, int err) {
    chatroom->err_code = err;
    if (chatroom->server_fd != -1) {
        close(chatroom->server_fd);
        chatroom->server_fd = -1;
    }
    return err == 0;
}

// Start the server and handle possible failures
bool start_server(upd_chatroom* chatroom) {
    chatroom->server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(chatroom->server_fd < 0) {
        return close_server(chatroom, 1);
    }
    if(bind(chatroom->server_fd, (struct sockaddr *)&chatroom->address, sizeof(chatroom->address)) < 0) {
        return close_server(chatroom, 2);
    }
    printf("Server started on port %d\n", chatroom->port);
    return close_server(chatroom, 0);  // success (0)
}

// get the vector index of clients according to a client_addr
size_t get_conn_idx(upd_chatroom *chatroom, struct sockaddr_in client_addr) {
    for (int i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *chatroom_addr = vector__access(conn_ctx, i, chatroom->clients.data);
        if ((client_addr.sin_addr.s_addr == chatroom_addr->conn_addr.sin_addr.s_addr) &&
            (client_addr.sin_port == chatroom_addr->conn_addr.sin_port) && 
            (client_addr.sin_family == chatroom_addr->conn_addr.sin_family)) {
            return i;
        }
    }
    return -1;
}

// Whether an addr is already in the clients<> pool or not
bool is_connected(upd_chatroom *chatroom, struct sockaddr_in client_addr) {
    return get_conn_idx(chatroom, client_addr) != -1;
}

// Simplify the socket send function.
int simple_send(upd_chatroom *chatroom, const void *buff, size_t n, struct sockaddr_in client_addr) {
    return sendto(chatroom->server_fd, buff, n, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
}

bool notify_reset_conn(upd_chatroom *chatroom, const void *msg, size_t size_of_msg, conn_ctx *ctx, bool clean_client) {
    int ret1 = simple_send(chatroom, msg, size_of_msg, ctx->conn_addr);
    int ret2 = simple_send(chatroom, connection_reset, sizeof(connection_reset), ctx->conn_addr);
    int ret3 = 1;
    if (clean_client) {
        clear_conn(ctx);
    } else {
        ret3 = simple_send(chatroom, main_menu, sizeof(main_menu), ctx->conn_addr);
        reset_conn(ctx);
    }
    return (ret1 >= 0) && (ret2 >= 0) && (ret3 >= 0);
}

// convert an addr to a message
char* addr_to_msg(const struct sockaddr_in addr) {
    char ip_cstr[INET_ADDRSTRLEN];
    strncpy(ip_cstr, inet_ntoa(addr.sin_addr), INET_ADDRSTRLEN);
    char *msg = malloc(strlen(ip_cstr) + 1);
    strcpy(msg, ip_cstr);
    return msg;
}

// Get the index of clients<> according to a user_uid
long int get_client_idx(upd_chatroom *chatroom, char *user_uid) {
    for (long int i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients.data);
        if (strcmp(ctx->conn_bind_uid, user_uid) == 0) {
            return i;
        }
    }
    return -1;
}

bool is_user_signed_in(upd_chatroom *chatroom, char* *username) {
    return get_client_idx(chatroom, username) != -1;
}

// Broadcasting to all connected clients (include or exclude current/self).
size_t system_broadcasting(upd_chatroom *chatroom, bool include_self, char *username, char* msg_body) {
    char *msg = "[SYSTEM_BROADCAST]: [UID]";
    // msg += username;

}

int main() {
    printf("Hello, World!\n");
    return 0;
}