#ifndef VALID_UTILS_H
#define VALID_UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <netinet/in.h>
#ifdef _WIN32 //Windows specific application
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif // _WIN32
#define SA struct sockaddr

#define VALID_INPUT_SIZE 20
#define USER_ROLE_SIZE 5
#define USER_ROLE "user"
#define CONN_STRING "127.0.0.1:8888"
#define CA_PEM "keys/ca/ca_cert.pem"
#define CERT_PEM "keys/client/client_cert.pem"
#define KEY_PEM "keys/client/private/client_key.pem"
#define PATH_SIZE 100
#define SERVER_ADDR_SIZE 100

// Server specific responses :
#define SUCCESS 0
#define INVALID_HIERARCHY_AUTHORIZATION_MESSAGE 2466
#define INVALID_AUTHORIZATION_MESSAGE 2446
#define INVALID_OBJECT_MESSAGE 1
#define DUPLICATE_VALUE_MESSAGE 101
#define GENERIC_MESSAGE 2
#define INVALID_DEVICE -1


typedef struct USER_CONTEXT USER_CONTEXT;
typedef struct LOGIN_CONTEXT LOGIN_CONTEXT;
typedef struct SEAL_CONTEXT SEAL_CONTEXT;
typedef struct PERSISTED_CONTEXT PERSISTED_CONTEXT;
typedef struct SSL_CONNECTION_CONTEXT SSL_CONNECTION_CONTEXT;
typedef struct SSL_RESPONSE SSL_RESPONSE;
typedef struct DISK_CONTEXT DISK_CONTEXT;
typedef struct AUTH_CONTEXT AUTH_CONTEXT;
typedef struct LOGGER_CONTEXT LOGGER_CONTEXT;

struct USER
{
    char userName[VALID_INPUT_SIZE];
    char userEmail[VALID_INPUT_SIZE];
    char userPassword[VALID_INPUT_SIZE];
    char userRole[USER_ROLE_SIZE];
};

struct LOGIN_DATA
{
    char userEmail[VALID_INPUT_SIZE];
    char userPassword[VALID_INPUT_SIZE];
};

struct SEAL_CONTEXT{
    char ownerAuth[VALID_INPUT_SIZE];
    char srkAuth[VALID_INPUT_SIZE];
    char dekAuth[VALID_INPUT_SIZE];
    char data[PATH_SIZE];
    char objectName[VALID_INPUT_SIZE];
};

struct PERSISTED_CONTEXT
{
    char indexName[VALID_INPUT_SIZE];
    char ownerPassword[VALID_INPUT_SIZE];
    char data[PATH_SIZE];
    int indexValue;
    char indexPassword[VALID_INPUT_SIZE];
    int dataSize;
};

struct SSL_CONNECTION_CONTEXT
{
    char conn_string[PATH_SIZE];
    char ca_pem[PATH_SIZE];
    char cert_pem[PATH_SIZE];
    char key_pem[PATH_SIZE];
};

struct SSL_RESPONSE
{
    int status;
    char activity[VALID_INPUT_SIZE];
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

struct LOGGER_CONTEXT
{
    char server_addr[SERVER_ADDR_SIZE];
    char file_path[PATH_SIZE];
};

void get_number(int *number);
void get_string(char *string_, int string_len);
void get_user_password(char *string_, int string_len);
void get_password(char *string_1, int string_len);
void get_ip_and_port(char *conn_str, int length);
int ssl_integer_send(SSL *ssl, int value);
int ssl_integer_receive(SSL *ssl, int* value);
void ssl_status(SSL *ssl, int return_bytes);
int read_ssl_request_response(SSL *ssl);

#endif // VALID_UTILS_H
