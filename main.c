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

void msg_attr_reset(msg_attr *msg_attr) {
    msg_attr->msg_attr_mask = 0;
    free(msg_attr->target_uid);  // todo check if it properly cleans
    msg_attr->target_ctx_idx = -1;
    msg_attr->is_set = false;
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

void set_bind_uid(conn_ctx *ctx, char* conn_bind_uid) {
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
    if (!username || !password) return false;  // todo check for empty
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

bool is_user_signed_in(upd_chatroom *chatroom, char *username) {
    return get_client_idx(chatroom, username) != -1;
}

// Broadcasting to all connected clients (include or exclude current/self).
size_t system_broadcasting(upd_chatroom *chatroom, bool include_self, char *username, char* msg_body) {
    char *msg = "[SYSTEM_BROADCAST]: [UID]";
    strcat(msg, username); strcat(msg, ": "); strcat(msg, msg_body);
    size_t sent_out = 0;
    for (size_t i = 0; i < chatroom->clients.size; i++) {
        conn_ctx *ctx = vector__access(conn_ctx, i, chatroom->clients.data);
        if (ctx->conn_status != 6) continue;
        if (strcmp(ctx->conn_bind_uid, username) == 0 && !include_self) continue;
        // if (include_self || strcmp(ctx->conn_bind_uid, username) != 0) {
        //     sent_out += simple_send(chatroom, msg, strlen(msg), ctx->conn_addr);
        // }  // good solution, but:
        if (simple_send(chatroom, msg, strlen(msg), ctx->conn_addr) >= 0) {
            sent_out++;
        }  // todo: check if it's possible to use vector__foreach(conn_ctx, ctx, chatroom->clients.data, simple_send(chatroom, msg, strlen(msg), ctx->conn_addr))
    }
    return sent_out;
}

const char* get_current_time(void) {
    time_t now;
    struct tm *tm_now;

    now = time(NULL);
    tm_now = localtime(&now);

    return asctime(tm_now);
}

int msg_precheck(upd_chatroom *chatroom, const conn_ctx *this_ctx, const char *buff_str, msg_attr *attr) {
    msg_attr_reset(attr);
    /*auto is_private_msg = (std::memcmp(buff_str.c_str(), to_user, MSG_ATTR_LEN) == 0);
    auto is_tagged_msg = (std::memcmp(buff_str.c_str(), tag_user, MSG_ATTR_LEN) == 0);*/
    bool is_private_msg = memcmp(buff_str, to_user, MSG_ATTR_LEN) == 0;
    bool is_tagged_msg = memcmp(buff_str, tag_user, MSG_ATTR_LEN) == 0;
    if (is_private_msg || is_tagged_msg) {
        const size_t start_pos = sizeof(to_user);
        char *delim_pos = strchr(buff_str + start_pos, user_delim);
        char *target_user;
        if (delim_pos == NULL) {
            target_user = strdup(buff_str + start_pos);
        } else {
            *delim_pos = '\0';
            target_user = strdup(buff_str + start_pos);
            *delim_pos = user_delim;
        }
        if (strcmp(target_user, this_ctx->conn_bind_uid) == 0) {
            return -1;  // user cannot tag or send private messages to self
                        // will not set the attributes
        }
        if (is_in_db(chatroom->user_db, target_user))/*if target user is valid*/ {
            if (!is_user_signed_in(chatroom, target_user)) { 
                return 1;  // tagged or private message requires target user signed in.
                        // false will bounce the msg back to sender.
                        // will not set the attributes.
            }
            attr->target_uid = target_user;
            attr->target_ctx_idx = get_client_idx(chatroom, target_user);
            attr->is_set = true;  // attributes set
            if (!is_private_msg) {
                attr->msg_attr_mask = 1;  // public but tagged
            } else {
                attr->msg_attr_mask = 2;  // private
            }
            return 0;  // msg_attr_mask set and return true
        }
        attr->is_set = true;  // attributes set
        return 0;  // if the target user uid is invalid, do nothing
    }
    attr->is_set = true;  // attributes set
    return 0;  // if normal message, do nothing
}

// assemble the message header for a connection context
char *assemble_msg_header(const conn_ctx *ctx) {
    struct sockaddr_in addr = ctx->conn_addr;
    char ip_cstr[INET_ADDRSTRLEN];
    strncpy(ip_cstr, inet_ntoa(addr.sin_addr), INET_ADDRSTRLEN);
    char *curr_time = get_current_time();
    /*std::ostringstream oss;
    oss << std::endl << curr_time << " [FROM_ADDR] " 
    << ip_cstr << ":" << ntohs(addr.sin_port) 
    << " [FROM_UID] " << ctx.get_bind_uid() << ":" << std::endl << "----  ";*/
    char *msg_header = malloc(strlen(curr_time) + strlen(ip_cstr) + strlen(ctx->conn_bind_uid) + 100);
    sprintf(msg_header, "\n%s [FROM_ADDR] %s:%d [FROM_UID] %s:\n----  ", curr_time, ip_cstr, ntohs(addr.sin_port), ctx->conn_bind_uid);
    return msg_header;
}

void tag_msg(char **msg_header, char *target_user) { 
    char *msg_header_tagged = malloc(strlen(*msg_header) + strlen(target_user) + 10); 
    sprintf(msg_header_tagged, "%s@tagged@%s ", *msg_header, target_user); 
    free(*msg_header); 
    *msg_header = msg_header_tagged; 
}

void priv_msg(char *msg_header, char *target_user) {
    char *msg_header_priv = malloc(strlen(msg_header) + strlen(target_user) + 10);
    sprintf(msg_header_priv, "%s*privto*%s ", msg_header, target_user);
    free(msg_header);
    msg_header = msg_header_priv;
}

// must call msg_precheck first
bool update_msg_buffer(struct vector(char) *buffer, const msg_attr *attr, const conn_ctx *ctx) {
    if (!attr->is_set) return false;
    char *msg_header = assemble_msg_header(ctx);
    if (attr->msg_attr_mask != 0) {
        // erase vector
        vector__delete(char, buffer->data, buffer->size, NULL, buffer);
    }
    if (attr->msg_attr_mask == 1) {
        // do msg_header += (std::string("@tagged@") + attr.target_uid + std::string(" "));
        tag_msg(msg_header, attr->target_uid);
    } else if (attr->msg_attr_mask == 2) {
        // do msg_header += (std::string("*privto*") + attr.target_uid + std::string(" "));
        priv_msg(msg_header, attr->target_uid);
    }
    // do buffer.insert(buffer.begin(), msg_header.c_str(), msg_header.c_str() + msg_header.size());
    // first we should create a slice
    struct slice(char) msg_header_slice = slice__create(char, &msg_header, strlen(msg_header));
    vector__insert(char, (char *)vector__begin(char, *buffer), msg_header_slice, buffer);  // todo check it
    vector__push_back(char, '\n', buffer);
    vector__push_back(char, '\n', buffer);
    vector__push_back(char, '\0', buffer);
    return true;
}

char *user_list_to_msg(upd_chatroom *chatroom) {  // todo write signed in users etc
    char *user_list_msg = malloc(100);
    sprintf(user_list_msg, "Currently signed in users: %d\n", chatroom->clients.size);
    return user_list_msg;
}

void fill(struct vector(char) *buffer) {
    // should do std::fill(buffer.begin(), buffer.end(), 0);
    for (size_t i = 0; i < buffer->capacity - 1; i++) {
        vector__push_back(char, 0, buffer);
    }
    vector__push_back(char, '\0', buffer);
}

// main processing method
int run_server(upd_chatroom *chatroom) {
    if (chatroom->server_fd == -1) {
        printf("Server not initialized\n");
        return -1;
    }
    struct sockaddr_in client_addr;
    size_t addr_len = sizeof(client_addr);
    struct vector(char) buffer = vector__create(char);
    char *msg_header;
    ctx_user_bind_buffer bind_buffer;
    while (true) {
        fill(&buffer);
        size_t bytes_recv = recvfrom(chatroom->server_fd, buffer.data, buffer.size, \
            MSG_WAITALL, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
        if (bytes_recv < 0) return close_server(chatroom, -3);
        vector__push_back(char, '\0', buffer);
        char *buff_str = (char *)buffer.data;
        /*std::cout << ">> Received from: " << std::endl << inet_ntoa(client_addr.sin_addr) \
        << ':' << ntohs(client_addr.sin_port) << '\t' << buffer.data() << std::endl;*/
        printf(">> Received from: %s:%d\t%s\n", inet_ntoa(client_addr.sin_addr),\
            ntohs(client_addr.sin_port), buff_str);
        size_t conn_idx = get_conn_idx(chatroom, client_addr);

        // new connection, initialize it
        if (conn_idx == chatroom->clients.size) {
            char *empty_uid = malloc(1);
            empty_uid[0] = '\0';
            conn_ctx *new_conn = conn_ctx_init(client_addr, empty_uid, 1);
            if (simple_send(chatroom, main_menu, sizeof(main_menu), client_addr) < 0) {
                printf("Error sending main menu\n");
                return close_server(chatroom, -4);
            }
            vector__push_back(conn_ctx*, new_conn, chatroom->clients);
            continue;
        }

        // conn_idx is valid. Start processing
        conn_ctx *client = vector__access(conn_ctx, conn_idx, chatroom->clients);
        int stat = client->conn_status;
        if (stat == 0) {
            simple_send(chatroom, main_menu, sizeof(main_menu), client_addr);
            client->conn_status = 1;
            continue;
        }
        if (stat == 100) {  // waiting for yes or no
            if (strcmp(buff_str, "yes") != 0 && strcmp(buff_str, "no") != 0) {
                notify_reset_conn(chatroom, not_yes_or_no, sizeof(not_yes_or_no), client, false);
                continue;
            }
            if (strcmp(buff_str, "yes") == 0) {
                simple_send(chatroom, input_password, sizeof(input_password), client_addr);
                size_t prev_ctx_idx = bind_buffer.ctx_idx_prev;
                conn_ctx *prev_ctx = vector__access(conn_ctx, prev_ctx_idx, chatroom->clients);
                struct sockaddr_in *prev_client_addr = get_conn_addr(prev_ctx);
                simple_send(chatroom, another_sign_warn, sizeof(another_sign_warn), *prev_client_addr);
                client->conn_status = 5;
                set_bind_uid(prev_ctx, client->conn_bind_uid);
            } else {
                notify_reset_conn(chatroom, option_denied, sizeof(option_denied), client, false);
            }
            continue;
        }
        if (stat == 1) {
            if (strcmp(buff_str, "1") != 0 && strcmp(buff_str, "2") != 0) {
                notify_reset_conn(chatroom, option_error, sizeof(option_error), client, false);
                continue;
            }
            if (strcmp(buff_str, "1") == 0) {
                simple_send(chatroom, input_username, sizeof(input_username), client_addr);
                client->conn_status = 2;  // sing up
            } else {
                simple_send(chatroom, input_password, sizeof(input_password), client_addr);
                client->conn_status = 3;  // sign in
            }
            continue;
        }

        if (stat == 2 || stat == 3) {
            int flag = user_uid_check(buff_str);
            if (flag == -1) {
                notify_reset_conn(chatroom, invalid_uid_len, sizeof(invalid_uid_len), client, false);
                continue;
            } 
            if (flag == 0) {
                notify_reset_conn(chatroom, invalid_uid_fmt, sizeof(invalid_uid_fmt), client, false);
                continue;
            }
            if (stat == 2) {
                if (is_in_db(chatroom->user_db, buff_str)) {
                    notify_reset_conn(chatroom, user_uid_exist, sizeof(user_uid_exist), client, false);
                    continue;
                }
                simple_send(chatroom, input_password, sizeof(input_password), client_addr);
                client->conn_status = 4;
                set_bind_uid(client, buff_str);
                continue;
            }

            if (!is_in_db(chatroom->user_db, buff_str)) {
                notify_reset_conn(chatroom, user_uid_error, sizeof(user_uid_error), client, false);
                continue;
            }
            size_t client_idx = get_client_idx(chatroom, buff_str);
            if (client_idx != chatroom->clients.size) {
                simple_send(chatroom, user_already_signin, sizeof(user_already_signin), client_addr);
                struct sockaddr_in *client_addr = get_conn_addr(vector__access(conn_ctx, client_idx, chatroom->clients));
                char *addr_msg = addr_to_msg(*client_addr);
                simple_send(chatroom, addr_msg, strlen(addr_msg), *client_addr);
                simple_send(chatroom, user_resign_in, sizeof(user_resign_in), *client_addr);
                set_bind_buffer(&bind_buffer, buff_str, client_idx);
                client->conn_status = 100;
                free(addr_msg);
                continue;
            }
            simple_send(chatroom, input_password, sizeof(input_password), client_addr);
            client->conn_status = 5;
            set_bind_uid(client, buff_str);
            continue;
        }

        if (stat == 4 || stat == 5) {
            char *user_uid = client->conn_bind_uid;
            int flag = pass_check(buff_str);
            if (stat == 4) {
                if (flag == -1) {
                    notify_reset_conn(chatroom, invalid_pass_len, sizeof(invalid_pass_len), client, false);
                    continue;
                }
                if (flag == 0) {
                    notify_reset_conn(chatroom, invalid_pass_fmt, sizeof(invalid_pass_fmt), client, false);
                    continue;
                }
                add_user(chatroom->user_db, user_uid, buff_str);
                set_user_status(chatroom->user_db, user_uid, 1);
                char *user_list_msg = user_list_to_msg(chatroom);
                simple_send(chatroom, signup_ok, sizeof(signup_ok), client_addr);
                simple_send(chatroom, user_list_msg, strlen(user_list_msg), client_addr);
                char *msg_body = " signed up and in\n\n";
                system_broadcasting(chatroom, false, user_uid, msg_body);
                free(user_list_msg);
                client->conn_status = 6;
                continue;
            }
            if (flag != 0) {
                notify_reset_conn(chatroom, invalid_pass, sizeof(invalid_pass), client, false);
                continue;
            }
            if (!is_pass_valid(chatroom->user_db, user_uid, buff_str)) {
                notify_reset_conn(chatroom, user_password_error, sizeof(user_password_error), client, false);
                continue;            
            }
            set_user_status(chatroom->user_db, user_uid, 1);
            char *user_list_msg = user_list_to_msg(chatroom);
            simple_send(chatroom, signin_ok, sizeof(signin_ok), client_addr);
            simple_send(chatroom, user_list_msg, strlen(user_list_msg), client_addr);
            char *msg_body = " signed in\n\n";
            system_broadcasting(chatroom, false, user_uid, msg_body);
            if (bind_buffer.is_set) {
                size_t prev_ctx_idx = bind_buffer.ctx_idx_prev;
                conn_ctx *prev_ctx = vector__access(conn_ctx, prev_ctx_idx, chatroom->clients);
                struct sockaddr_in *prev_client_addr = get_conn_addr(prev_ctx);
                notify_reset_conn(chatroom, client_switched, sizeof(client_switched), prev_ctx, true);
                unset_bind_buffer(&bind_buffer);
            }
            free(user_list_msg);
            client->conn_status = 6;
            continue;
        }

        char *user_uid = client->conn_bind_uid;
        if (strcmp(buff_str, "~:q!")) {
            notify_reset_conn(chatroom, signed_out, sizeof(signed_out), client, true);
            char *msg_body = " signed out!\n\n";
            system_broadcasting(chatroom, false, user_uid, msg_body);
            set_user_status(chatroom->user_db, user_uid, 0);
            continue;
        }
        if (strcmp(buff_str, "~:lu")) {
            char *user_list_msg = user_list_to_msg(chatroom);
            simple_send(chatroom, user_list_msg, strlen(user_list_msg), client_addr);
            free(user_list_msg);
            continue;
        }
        // if empty then skip
        if (buff_str[0] == '\0') {
            continue;
        }
        msg_attr attr;
        int check = msg_precheck(chatroom, client, buff_str, &attr);
        if (check == 1) {
            simple_send(chatroom, cannot_at_or_to_user, sizeof(cannot_at_or_to_user), client_addr);
            continue;
        }
        if (check == -1) {
            simple_send(chatroom, cannot_at_or_to_self, sizeof(cannot_at_or_to_self), client_addr);
            continue;
        }
        if (!update_msg_buffer(&buffer, &attr, client)) {
            char *internal_bug = "internal error, probably a bug. Please report to us.\n";
            system_broadcasting(chatroom, true, "[ALL]", internal_bug);
            continue;
        }
        if (attr.msg_attr_mask == 0) {
            for (size_t i = 0; i < chatroom->clients.size; i++) {
                conn_ctx *item = vector__access(conn_ctx, i, chatroom->clients);
                if (item->conn_status == 6) {
                    if (strcmp(item->conn_bind_uid, attr.target_uid)) {
                        // extract target client
                        size_t target_ctx_idx = attr.target_ctx_idx;
                        conn_ctx *target_ctx = vector__access(conn_ctx, target_ctx_idx, chatroom->clients);
                        struct sockaddr_in *target_client_addr = get_conn_addr(target_ctx);
                        simple_send(chatroom, been_tagged, sizeof(been_tagged), *target_client_addr);
                        simple_send(chatroom, buffer.data, buffer.size, *target_client_addr);  // todo check it
                    }
                }
            }
            continue;
        }
        simple_send(chatroom, private_msg_sent, sizeof(private_msg_sent), client_addr);
        simple_send(chatroom, buffer.data, buffer.size, client_addr);
        // extract target client
        size_t target_ctx_idx = attr.target_ctx_idx;
        conn_ctx *target_ctx = vector__access(conn_ctx, target_ctx_idx, chatroom->clients);
        struct sockaddr_in *target_client_addr = get_conn_addr(target_ctx);
        simple_send(chatroom, private_msg_recved, sizeof(private_msg_recved), *target_client_addr);
        simple_send(chatroom, buffer.data, buffer.size, *target_client_addr);
    }
}

int main() {
    printf("Hello, World!\n");
    upd_chatroom *new_server = upd_chatroom_init(default_port, init_buffsize);
    if (!start_server(new_server)) {
        printf("Failed to start server\n");
        return 1;
    }
    run_server(new_server);
    return 0;
}