#ifndef VALID_UTILS_H
#define VALID_UTILS_H

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define PATH_SIZE 100
#define VALID_INPUT_SIZE 20
#define SERVER_ADDR_SIZE 100
#define PORT "8888"

/*
#define PORT "8888"
#define CA_PEM "keys/ca/ca_cert.pem"
#define CERT_PEM "keys/server/server_cert.pem"
#define KEY_PEM "keys/server/private/server_key.pem"
*/

// PRE defined string for API activities
#define USER_REGISTER "register"
#define USER_LOGIN "login"
#define CLEAR_TPM "clear tpm"
#define ADD_KEY "Add Key"
#define GET_KEY "Get Key"
#define ENCRYPT_DISK "encrypt disk"
#define OPEN_DISK "open disk"
#define CHANGE_AUTH "Change Password"
#define WRITE_LOG_TO_JSON "Write log to JSON"
#define UPLOAD_LOG_TO_CLOUD "Upload log to cloud"


typedef struct SSL_CONNECTION_CONTEXT SSL_CONNECTION_CONTEXT;
typedef struct SSL_RESPONSE SSL_RESPONSE;
typedef struct DISK_CONTEXT DISK_CONTEXT;
typedef struct AUTH_CONTEXT AUTH_CONTEXT;
typedef struct CLIENT CLIENT;
typedef struct LOGGER_CONTEXT LOGGER_CONTEXT;

struct CLIENT
{
    char address[PATH_SIZE];
};

struct DISK_CONTEXT
{
    char device_name[VALID_INPUT_SIZE];
    char key_file_name[PATH_SIZE];
    char key_password[PATH_SIZE];
};

struct AUTH_CONTEXT
{
    char old_auth[VALID_INPUT_SIZE];
    char new_auth[VALID_INPUT_SIZE];
};

struct SSL_CONNECTION_CONTEXT
{
    char port_string[PATH_SIZE];
    char ca_pem[PATH_SIZE];
    char cert_pem[PATH_SIZE];
    char key_pem[PATH_SIZE];
};

struct SSL_RESPONSE
{
    int status;
    char activity[VALID_INPUT_SIZE];
};

struct LOGGER_CONTEXT
{
    char server_addr[SERVER_ADDR_SIZE];
    char file_path[PATH_SIZE];
};

void get_number(int *number);

int ssl_integer_send(SSL *ssl, int value);
int ssl_integer_receive(SSL *ssl, int* value);
int ssl_status(SSL *ssl, int return_bytes);
void log_server_api();
int check_file_exists(const char* file_path);

#endif
