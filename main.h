#include <stdio.h>
#include <stdint.h>

#define SALT_LENGTH 16
#define HASH_LENGTH 64
#define ITERATIONS 100000

const size_t uid_maxlen = 64;  // todo maybe short int?
const size_t uid_minlen = 4;
const size_t password_maxlen = 32;
const size_t password_minlen = 4;
const uint16_t default_port = 8081;
const size_t init_buffsize = 4096;
const char special_chars[] = "~!@#$^&(){}[]-_=+;:,.<>/|";  // todo include %
const char main_menu[] = "1. singup\n2. singin\nPlease chose (1 | 2): ";
const char input_username[] = "Username: ";
const char input_password[] = "Password: ";
const char option_error[] = "Invalid option";
const char user_uid_exist[] = "user already exists.\n";
const char user_uid_error[] = "user does not exists.\n";
const char user_password_error[] = "wrong password.\n";
const char invalid_uid_fmt[] = "invalid uid format, rules to follow:\n\
    4-64 ascii chars.\n\
    a-z, A-Z, numbers, and/or hyphen-.\n";
const char invalid_uid_len[] = "invalid uid length: 4-64\n";
const char invalid_pass_fmt[] = "invalid password format, rules to follow:\n\
    4-32 ascii chars.\n\
    a-z, A-Z, numbers, and/or special chars: ~ ! @ # $ ^ & ( ) { } [ ] - _ = + ; : . , < > / |\n";
const char invalid_pass[] = "not a valid password string.\n";
const char invalid_pass_len[] = "invalid password length: 4-32\n";
const char signup_ok[] = "[SYSTEM_WELCOME] signed up and signed in.\n\
[SYSTEM_WELCOME] send ~:q! to sign out.\n\
[SYSTEM_WELCOME] send ~-@uid: to tag another user.\n\
[SYSTEM_WELCOME] send ~->uid: to send private messages to another user.\n\n";
const char signin_ok[] = "[SYSTEM_WELCOME] signed in.\n\
[SYSTEM_WELCOME] send ~:q! to sign out.\n\
[SYSTEM_WELCOME] send ~-@uid: to tag another user.\n\
[SYSTEM_WELCOME] send ~->uid: to send private messages to another user.\n\n";
const char password_not_complex[] = "the password is not complex enough.\n";
const char signed_out[] = "[SYSTEM] you have signed out.\n";
const char user_already_signin[] = "user already signed in at client: ";
const char user_resign_in[] = "this signin would quit that client, are you sure? (yes | no)\n";
const char another_sign_warn[] = "[SYSTEM_WARN] another client is trying to sign in your uid!\n";
const char not_yes_or_no[] = "option error, please send either yes or no\n";
const char option_denied[] = "you sent no. nothing changed.\n";
const char client_switched[] = "you've resigned in on another client. signed out here.\n";
const char connection_reset[] = "this connection has been reset.\n\n";
const char cannot_at_or_to_user[] = "[SYSTEM] target user not signed in.\n";
const char cannot_at_or_to_self[] = "[SYSTEM] you cannot tag or send privated messages to yourself.\n";
const char been_tagged[] = "[SYSTEM_NOTIFY] you've been tagged!";
const char private_msg_recved[] = "[SYSTEM_NOTIFY] you've received a private message!";
const char private_msg_sent[] = "[SYSTEM_INFO] you've sent a private message!";
const size_t MSG_ATTR_LEN = 3;
const char to_user[MSG_ATTR_LEN] = {'~', '-', '>'};
const char tag_user[MSG_ATTR_LEN] = {'~', '-', '@'};
const char user_delim = ':';