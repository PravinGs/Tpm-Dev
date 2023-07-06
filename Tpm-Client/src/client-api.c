#include "client-api.h"
#include <cjson/cJSON.h>

char client_address[PATH_SIZE];

void home_page(SSL *ssl)
{
    int router_point = -1;
    printf("Enter 1 to register 2 to login 3 to exit\n");
    get_number(&router_point);
    ssl_integer_send(ssl, router_point);
    switch(router_point)
    {
    case 1:
        register_user(ssl);
        break;
    case 2:
        if (login_user(ssl, 1))
        {
            tpm_page(ssl);
        }
        break;
    case 3:
        exit(0);
    default:
        printf("please enter valid input\n");
        home_page(ssl);
    }
}

void configure_tpm(SSL *ssl)
{
    int router_point = 0;
    printf("1 - Clear Tpm\n2 - Change Hierarchy Password\n3 - Back\n");
    get_number(&router_point);
    ssl_integer_send(ssl, router_point);
    switch(router_point)
    {
    case 1:
        clear_tpm(ssl);
        break;
    case 2:
        changeHierarchyPassword(ssl);
        break;
    case 3:
        tpm_page(ssl);
        break;
    default:
        printf("Please provide valid input.\n");
        configure_tpm(ssl);
    }
}

void tpm_page(SSL *ssl)
{
    int flag = 0;
    printf("TPM Configuration Page.\n1 - Tpm-Configuration\n2 - Add Keys to the TPM\n3 - Get Key\n4 - Disk Encryption\n5 - home page\n");
    get_number(&flag);
    ssl_integer_send(ssl, flag);
    switch(flag)
    {
    case 1:
        //TPM CLEAR
        configure_tpm(ssl);
        break;
    case 2:
        //TPM SEAL
        //add_key_nv_ram(ssl);
        seal_data(ssl);
        break;
    case 3:
        // TPM UNSEAL
        //get_key_nv_ram(ssl);
        unseal_data(ssl);
        break;
    case 4:
        printf("Disk Encryption Page\n");
        disk_encryption_page(ssl);
        break;
    case 5:
        home_page(ssl);
        break;
    default:
        printf("Please enter valid input.\n");
        tpm_page(ssl);
    }
}

void disk_encryption_page(SSL *ssl)
{
    int router_point = 0;
    printf("1 - Encrypt Disk\n2 - Decrypt Disk\n3 - Back\n");
    get_number(&router_point);
    ssl_integer_send(ssl, router_point);
    switch(router_point)
    {
    case 1:
        printf("Encryption on a given disk\n");
        if (add_key_nv_ram(ssl) == 0)
        {
            encrypt_disk(ssl);
        }
        break;
    case 2:
        printf("Decryption on a given disk\n");
        decrypt_disk(ssl);
        break;
    case 3:
        tpm_page(ssl);
        break;
    default:
        printf("Enter valid input\n");
        disk_encryption_page(ssl);
    }
}

void encrypt_disk(SSL *ssl)
{
    int ssl_response = 0;
    struct DISK_CONTEXT context;
    int validation_response = 0;
    printf("******This will erase all data in your disk, keep backup before doing it.******\n");
    printf("Enter the device name : ");
    get_string(context.device_name, VALID_INPUT_SIZE);
    printf("Enter key name: ");
    get_string(context.key_file_name, PATH_SIZE);
    printf("Enter key password: ");
    get_string(context.key_password, VALID_INPUT_SIZE);

    ssl_response = SSL_write(ssl, &context, (int)sizeof(struct DISK_CONTEXT));
    ssl_status(ssl, ssl_response);
    ssl_integer_receive(ssl, &validation_response);
    if(validation_response != 0)
    {
        printf("Invalid Key file or password.\n");

    }
    else
    {
        read_ssl_request_response(ssl);
    }
    disk_encryption_page(ssl);
}

void decrypt_disk(SSL *ssl)
{
    int ssl_response = 0;
    struct DISK_CONTEXT context;
    int validation_response = 0;
    printf("Enter the device name : ");
    get_string(context.device_name, VALID_INPUT_SIZE);
    printf("Enter key name: ");
    get_string(context.key_file_name, PATH_SIZE);
    printf("Enter key password: ");
    get_user_password(context.key_password, VALID_INPUT_SIZE);

    ssl_response = SSL_write(ssl, &context, (int)sizeof(struct DISK_CONTEXT));
    ssl_status(ssl, ssl_response);
    ssl_integer_receive(ssl, &validation_response);
    if (validation_response != 0)
    {
        printf("Invalid Key Name / Password\n");
    }
    else
    {
        read_ssl_request_response(ssl);
    }
    disk_encryption_page(ssl);

}

void register_user(SSL *ssl)
{
    int flag = 0;
    int ssl_response = 0;
    struct USER user;
    printf("Registration page\n");
    while(1)
    {
        printf("Enter Your Name: ");
        get_string(user.userName, VALID_INPUT_SIZE);
        printf("Enter Your Email: ");
        get_string(user.userEmail, VALID_INPUT_SIZE);
        printf("Enter Your Password: ");
        get_password(user.userPassword, VALID_INPUT_SIZE);
        strncpy(user.userRole, USER_ROLE, (int)sizeof(user.userRole));
        ssl_response = SSL_write(ssl, &user, sizeof(struct USER));
        ssl_status(ssl, ssl_response);
        if (read_ssl_request_response(ssl) == 1)
        {
            printf("Profile registered successfully.\n");
            break;
        }
        else
        {
            printf("Invalid user details. Please give valid details.\n");
        }
    }
    printf("enter 1 to login 2 to back: ");
    get_number(&flag);
    ssl_response = ssl_integer_send(ssl, flag);
    switch (flag)
    {
    case 1:
        login_user(ssl, 1);
        break;
    case 2:
        home_page(ssl);
        break;
    default:
        home_page(ssl);
    }
}

int login_user(SSL *ssl, int login_status)
{
    int router = 0;
    int ssl_response = 0;
    struct LOGIN_DATA login_data;
    int login_response = 0;
    while(login_status) // Initial login 1
    {
        printf("Enter Email : ");
        get_string(login_data.userEmail, VALID_INPUT_SIZE);
        printf("Enter Password : ");
        get_user_password(login_data.userPassword, VALID_INPUT_SIZE);

        printf("%s, %s\n", login_data.userEmail, login_data.userPassword);
        ssl_response = SSL_write(ssl, &login_data, (int)sizeof(struct LOGIN_DATA));
        ssl_status(ssl, ssl_response);
        login_response = read_ssl_request_response(ssl);
        if (login_response > 0)
        {
            break;
        }
        printf("Login failed.\n");
    }
    printf("Please enter a number to the respective page\n1 - TPM Page\n2 - Logging Page\n3 - Home\n ");
    get_number(&router);
    ssl_integer_send(ssl, router);
    switch(router)
    {
    case 1:
        tpm_page(ssl);
        break;
    case 2:
        logger_page(ssl);
        break;
    case 3:
        home_page(ssl);
        break;
    default:
        home_page(ssl);
    }
    return login_response;
}

int add_key_nv_ram(SSL *ssl)
{
    struct PERSISTED_CONTEXT handle;
    int validation_response = 0;
    int function_response = 0;
    int ssl_response = 0;

    printf("Enter key file name:");
    get_string(handle.data, PATH_SIZE);
    printf("Enter owner password:");
    get_string(handle.ownerPassword, VALID_INPUT_SIZE);
    printf("Enter Password to the key file:");
    get_string(handle.indexPassword, VALID_INPUT_SIZE);
    printf("Enter name to this key:");
    get_string(handle.indexName, VALID_INPUT_SIZE);
    ssl_response = SSL_write(ssl, &handle, (int)sizeof(struct PERSISTED_CONTEXT));
    ssl_status(ssl, ssl_response);
    ssl_integer_receive(ssl, &validation_response);
    printf("Valid response: %d\n", validation_response);
    if (validation_response == 0)
    {
        printf("Invalid Key file entered.\n");
        return 1;
    }
    else
    {
        function_response = read_ssl_request_response(ssl);
    }
    return function_response;
}

int get_key_nv_ram(SSL *ssl)
{
    struct PERSISTED_CONTEXT handle;
    int ssl_response = 0;
    int function_response = 0;

    printf("Enter name to this key:");
    get_string(handle.indexName, VALID_INPUT_SIZE);
    printf("Enter owner password:");
    get_string(handle.ownerPassword, VALID_INPUT_SIZE);
    printf("Enter Password to the key file:");
    get_user_password(handle.indexPassword, VALID_INPUT_SIZE);
    ssl_response = SSL_write(ssl, &handle, (int)sizeof(PERSISTED_CONTEXT));
    ssl_status(ssl, ssl_response);
    function_response = read_ssl_request_response(ssl);
    return function_response;
}

void delete_key_nv_ram(SSL *ssl)
{
    struct PERSISTED_CONTEXT handle;
    int ssl_response = 0;

    printf("Enter name to this key:");
    get_string(handle.indexName, VALID_INPUT_SIZE);
    printf("Enter owner password:");
    get_string(handle.ownerPassword, VALID_INPUT_SIZE);
    printf("Enter Password to the key file:");
    get_string(handle.indexPassword, VALID_INPUT_SIZE);

    ssl_response = SSL_write(ssl, &handle, (int)sizeof(struct PERSISTED_CONTEXT));
    ssl_status(ssl, ssl_response);
    // Need update.

}

void clear_tpm(SSL *ssl)
{
    struct USER auth_user;
    int ssl_response = 0;

    printf("Enter lockout password : ");
    get_user_password(auth_user.userPassword, VALID_INPUT_SIZE);
    ssl_response = SSL_write(ssl, &auth_user, (int)sizeof(struct USER));
    ssl_status(ssl, ssl_response);
    read_ssl_request_response(ssl);
    configure_tpm(ssl);
}

void changeHierarchyPassword(SSL *ssl)
{
    int flag = 0;
    int ssl_response = 0;
    struct AUTH_CONTEXT auth;

    printf("1 - Owner\n2 - Platform\n3 - Endorsement\n4 - Lockout\nEnter(choice): ");
    get_number(&flag);
    ssl_integer_send(ssl, flag);
    printf("Enter Old Password: ");
    get_user_password(auth.old_auth, VALID_INPUT_SIZE);
    printf("Enter new Password: ");
    get_password(auth.new_auth, VALID_INPUT_SIZE);
    ssl_response = SSL_write(ssl, &auth, (int)sizeof(struct AUTH_CONTEXT));
    ssl_status(ssl, ssl_response);
    read_ssl_request_response(ssl);
    configure_tpm(ssl);
}

void seal_data(SSL *ssl)
{
    struct SEAL_CONTEXT seal;
    int ssl_response = 0;

    printf("Enter the path to the file: ");
    get_string(seal.data, PATH_SIZE);
    printf("Enter Owner Password: ");
    get_string(seal.ownerAuth, VALID_INPUT_SIZE);
    printf("Enter Primary Password: ");
    get_string(seal.srkAuth, VALID_INPUT_SIZE);
    printf("Enter Seal Password: ");
    get_string(seal.dekAuth, VALID_INPUT_SIZE);
    printf("Enter Object name:");
    get_string(seal.objectName, VALID_INPUT_SIZE);

    ssl_response = SSL_write(ssl, &seal, sizeof(struct SEAL_CONTEXT));
    ssl_status(ssl, ssl_response);
    read_ssl_request_response(ssl);
    tpm_page(ssl);
}

void unseal_data(SSL *ssl)
{
    struct SEAL_CONTEXT seal;
    int ssl_response = 0;

    printf("Enter key name: ");
    get_string(seal.objectName, VALID_INPUT_SIZE);
    printf("Enter key Password: ");
    get_user_password(seal.dekAuth, VALID_INPUT_SIZE);
    printf("Enter owner Password: ");
    get_user_password(seal.ownerAuth, VALID_INPUT_SIZE);
    ssl_response = SSL_write(ssl, &seal, (int)sizeof(struct SEAL_CONTEXT));
    ssl_status(ssl, ssl_response);
    read_ssl_request_response(ssl);
    tpm_page(ssl);

}

void logger_page(SSL *ssl)
{
    int router = 0;
    printf("1 - System Events\n2 - Application Events\n3 - Upload Log to Cloud\n4 - Go Back\n");
    get_number(&router);
    ssl_integer_send(ssl, router);
    switch(router)
    {
    case 1:
        get_system_event_log(ssl);
        break;
    case 2:
        get_application_log(ssl);
        break;
    case 3:
         send_log_server(ssl);
        break;
    case 4:
        login_user(ssl, 0);
        break;
    default:
        printf("Enter a valid input\n");
        logger_page(ssl);

    }
}

void send_log_server(SSL *ssl)
{
    int ssl_response = 0;
    struct LOGGER_CONTEXT logger;

    printf("Enter server url to send log file :");
    get_string(logger.server_addr, SERVER_ADDR_SIZE);
    printf("Enter log file path :");
    get_string(logger.file_path, PATH_SIZE);

    ssl_response = SSL_write(ssl, &logger, (int)sizeof(struct LOGGER_CONTEXT));
    ssl_status(ssl, ssl_response);
    read_ssl_request_response(ssl);
    logger_page(ssl);
}

void get_system_event_log(SSL *ssl)
{
    struct LOGGER_CONTEXT logger;
    int ssl_response = 0;

    printf("Enter syslog file path: ");
    get_string(logger.file_path, PATH_SIZE);
    printf("Enter file path to save json: ");
    get_string(logger.server_addr, SERVER_ADDR_SIZE);

    ssl_response = SSL_write(ssl, &logger, (int)sizeof(struct LOGGER_CONTEXT));
    ssl_status(ssl, ssl_response);
    read_ssl_request_response(ssl);
    logger_page(ssl);
}


void get_application_log(SSL *ssl)
{
     struct LOGGER_CONTEXT logger;
     int  ssl_response = 0;
     
     printf("Enter log file path: ");
     get_string(logger.file_path, PATH_SIZE);
     printf("Enter file path to save json: ");
     get_string(logger.server_addr, SERVER_ADDR_SIZE);
     
     ssl_response = SSL_write(ssl, &logger, (int)sizeof(struct LOGGER_CONTEXT));
     ssl_status(ssl, ssl_response);
     read_ssl_request_response(ssl);
     logger_page(ssl);
}

 

static SSL_CTX *get_client_context(const char *ca_pem,
                                   const char *cert_pem,
                                   const char *key_pem)
{
    SSL_CTX *ctx = NULL;

    /* Create a generic context */
    if (!(ctx = SSL_CTX_new(SSLv23_client_method())))
    {
        fprintf(stderr, "Cannot create a client context\n");
        return NULL;
    }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        fprintf(stderr, "Failed to set min protocol version.\n");
        goto fail;
    }

    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        fprintf(stderr, "Failed to set max protocol version.\n");
        goto fail;
    }


    /* Load the client's CA file location */
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
    {
        fprintf(stderr, "Cannot load client's CA file\n");
        goto fail;
    }

    /* Load the client's certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's certificate file\n");
        goto fail;
    }

    /* Load the client's key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's key file\n");
        goto fail;
    }

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Client's certificate and key don't match\n");
        goto fail;
    }

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the server's certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* We accept only certificates signed only by the CA himself */
    SSL_CTX_set_verify_depth(ctx, 1);

    /* Done, return the context */
    return ctx;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}

int client(SSL_CONNECTION_CONTEXT context)
{
    SSL* ssl = NULL;
    SSL_CTX *ctx = NULL;
    BIO *sbio = NULL;
    int r;
    int rc = -1;

    /* Initialize OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Get a context */
    if (!(ctx = get_client_context(context.ca_pem, context.cert_pem, context.key_pem)))
    {
        return rc;
    }

    /* Get a BIO */
    if (!(sbio = BIO_new_ssl_connect(ctx)))
    {
        fprintf(stderr, "Could not get a BIO object from context\n");
        goto fail1;
    }

    /* Get the SSL handle from the BIO */
    BIO_get_ssl(sbio, &ssl);

    /* Connect to the server */
    if (BIO_set_conn_hostname(sbio, context.conn_string) != 1)
    {
        fprintf(stderr, "Could not connection to the server\n");
        goto fail2;
    }

    /* Perform SSL handshake with the server */
    if ((r = SSL_do_handshake(ssl)) != 1)
    {
        printf("Error code : %d\n", SSL_get_error(ssl, r));
        if (r == SSL_ERROR_SYSCALL)
        {
            printf("SSL_ERROR_SYSCALL\n");
        }
        if (errno == ECONNRESET)
        {
            printf("ECONNRESET\n");
        }
        if (errno == ETIMEDOUT)
        {
            printf("ETIMEDOUT\n");
        }
        fprintf(stderr, "SSL Handshake failed\n");
        goto fail2;
    }

    /* Verify that SSL handshake completed successfully */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Verification of handshake failed\n");
        goto fail2;
    }

    /* Inform the user that we've successfully connected */
    printf("SSL handshake successful with %s\n", context.conn_string);
    strncpy(client_address, context.conn_string, (int)sizeof(client_address));
    client_address[(int) strlen(context.conn_string)] = '\0';
    home_page(ssl);

fail2:
    BIO_free_all(sbio);
fail1:
    SSL_CTX_free(ctx);
    return rc;
}

void usage()
{
    fprintf(stderr, "Usage: ./a.out "
            /* 2 */ "(server <port_num> | client <server_ip>:<server_port>) "
            /* 3 */ "<CAfile_pem> "
            /* 4 */ "<cert_pem> "
            /* 5 */ "<key_pem>\n");
}

