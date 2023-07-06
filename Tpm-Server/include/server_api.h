#ifndef SSL_CONNECTION_H
#define SSL_CONNECTION_H
#include "valid_utils.h"
#include "adminservice.h"
#include "sealservice.h"
#include "encryptservice.h"
#include "dbservice.h"
#include "disk_encryption.h"
#include <syslog.h>
#include <errno.h>
#include <pthread.h>


#define SUCCESS 0
#define INVALID_HIERARCHY_AUTHORIZATION_MESSAGE 2466
#define INVALID_AUTHORIZATION_MESSAGE 2446
#define INVALID_OBJECT_MESSAGE 1
#define DUPLICATE_VALUE_MESSAGE 101
#define GENERIC_MESSAGE 2
#define INVALID_DEVICE -1


int server(SSL_CONNECTION_CONTEXT context);
void register_user(SSL *ssl);
void login_user(SSL* ssl, int login_status);
void home_page(SSL* ssl);
void tpm_server(SSL *ssl, int flag);
void configure_tpm(SSL *ssl);
void clear_tpm(SSL *ssl);
void start_service(int flag);
int add_disk_encryption_key(SSL *ssl);
int get_disk_encryption_key(SSL *ssl, char*secret_data);
void disk_encryption_page(SSL *ssl);
void encrypt_disk(SSL *ssl);
void decrypt_disk(SSL *ssl);
void seal_data(SSL *ssl);
void unseal_data(SSL *ssl);
void saveLog(LOG_CONTEXT log, int response);
int write_ssl_request_response(SSL* ssl, char* name, int status);
void update_logout();

// Log Api
void logger_page(SSL *ssl);
void send_log_server(SSL *ssl);
void get_sys_event_log(SSL *ssl);
void get_app_log(SSL *ssl);
void shutdown_server();






#endif
