#ifndef CLIENT_API_H
#define CLIENT_API_H
#include "valid-utils.h"
#include <signal.h>

int client(SSL_CONNECTION_CONTEXT context);

// User Registration and login page
void register_user(SSL *ssl);
int login_user(SSL *ssl, int login_status);
void delete_user();
void get_user_details();

//Man Page

void home_page(SSL *ssl);
void tpm_page(SSL *ssl);
void disk_encryption_page(SSL *ssl);


void seal_data(SSL *ssl);
void unseal_data(SSL *ssl);
int add_key_nv_ram(SSL *ssl);
int get_key_nv_ram(SSL *ssl);
void delete_key_nv_ram(SSL *ssl); //Not completed.
void clear_tpm(SSL *ssl);
void changeHierarchyPassword(SSL *ssl);
void configure_tpm(SSL *ssl);

void encrypt_disk(SSL *ssl);
void decrypt_disk(SSL *ssl);

void logger_page(SSL *ssl);
void send_log_server(SSL *ssl);
void get_system_event_log(SSL *ssl);
void get_application_log(SSL *ssl);


#endif // CLIENT_API_H
