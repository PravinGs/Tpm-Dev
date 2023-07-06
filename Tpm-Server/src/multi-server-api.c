#include "server_api.h"
#include "myqueue.h"
#include "log-api.h"

#define THREAD_POOL_SIZE 25
#define APP_LOG_FILE "/var/log/tls-server.log"

static TSS2_TCTI_CONTEXT *tcti_context;
static ESYS_CONTEXT *esys_context;
static struct CLIENT client;
static int LOGIN_USER_ID = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

static const char * get_client_ip(SSL * ssl)
{
    int client_fd = SSL_get_fd(ssl);
    static char ip_address[INET6_ADDRSTRLEN];
    struct sockaddr_storage client_addr;
    socklen_t client_address_length = sizeof(client_addr);
    if (getpeername(client_fd, (struct sockaddr*)&client_addr, &client_address_length) == -1)
    {
        printf("Failed to get peer name");
        return ip_address;
    }
    if (client_addr.ss_family == AF_INET)
    {
        struct sockaddr_in* ipv4 = (struct sockaddr_in *)&client_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_address, INET_ADDRSTRLEN);
    }
    else if (client_addr.ss_family == AF_INET6)
    {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6 *)&client_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_address, INET6_ADDRSTRLEN);
    }

    return ip_address;
}

static void activity_log(SSL *ssl, const char * error_msg, int status)
{
    const char * ip_addr = get_client_ip(ssl);
    if (status == 0)
    {
        syslog(LOG_INFO, "[SUCCESS] %s, FROM = %s, PORT = %s", error_msg, ip_addr, PORT);
    }
    else
    {
        syslog(LOG_INFO, "[ERROR] %s, FROM = %s, PORT = %s", error_msg, ip_addr, PORT);
    }
    return ;
}

static void create_connection_log(struct sockaddr_in client_addr)
{
    syslog(LOG_INFO, "[ACCEPT] FROM = %s PORT = %s.\n", inet_ntoa(client_addr.sin_addr), PORT);
    return ;
}

static SSL_CTX *get_server_context(const char *ca_pem,const char *cert_pem,const char *key_pem)
{
    SSL_CTX *ctx = NULL;

    /* Get a default context */
    if (!(ctx = SSL_CTX_new(SSLv23_server_method())))
    {
        fprintf(stderr, "SSL_CTX_new failed\n");
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

    /* Set the CA file location for the server */
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
    {
        fprintf(stderr, "Could not set the CA file location\n");
        goto fail;
    }

    /* Load the client's CA file location as well */
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_pem));

    /* Set the server's certificate signed by the CA */
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Could not set the server's certificate\n");
        goto fail;
    }

    /* Set the server's key for the above certificate */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Could not set the server's key\n");
        goto fail;
    }

    /* We've loaded both certificate and the key, check if they match */
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Server's certificate and the key don't match\n");
        goto fail;
    }

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the client as well */
    SSL_CTX_set_verify(ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);

    /* We accept only certificates signed only by the CA himself */
    SSL_CTX_set_verify_depth(ctx, 1);

    /* Done, return the context */
    return ctx;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}

static int get_socket(int port_num)
{
    struct sockaddr_in sin;
    int sock, val;

    /* Create a socket */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "Cannot create a socket\n");
        return -1;
    }

    /* We don't want bind() to fail with EBUSY */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
    {
        fprintf(stderr, "Could not set SO_REUSEADDR on the socket\n");
        goto fail;
    }

    /* Fill up the server's socket structure */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port_num);

    /* Bind the socket to the specified port number */
    if (bind(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
        fprintf(stderr, "Could not bind the socket\n");
        goto fail;
    }

    /* Specify that this is a listener socket */
    if (listen(sock, SOMAXCONN) < 0)
    {
        fprintf(stderr, "Failed to listen on this socket\n");
        goto fail;
    }

    /* Done, return the socket */
    return sock;
fail:
    close(sock);
    return -1;
}

void shutdown_server()
{
    printf("Shut down server called.\n");
    SSL *ssl = NULL;
    int client_socket;
    pthread_mutex_lock(&mutex);
    ssl = dequeue();
    pthread_mutex_unlock(&mutex);

    while(ssl != NULL)
    {
    	client_socket = SSL_get_fd(ssl);
        printf("Client socket : %d\n", client_socket);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
        pthread_mutex_lock(&mutex);
        ssl = dequeue();
        pthread_mutex_unlock(&mutex);
    }

    return ;
}

static void *handle_client(void *arg)
{
    SSL* client_ssl = (SSL *)arg;
    home_page(client_ssl);
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    return NULL;
}

void * thread_function(void * args)
{
    while (true)
    {
        SSL *ssl = NULL;
        pthread_mutex_lock(&mutex);

        if ((ssl = dequeue()) == NULL)
        {
            pthread_cond_wait(&condition_var, &mutex);
            ssl = dequeue();
        }
        pthread_mutex_unlock(&mutex);
        if (ssl != NULL)
        {
            // We have work to do
            handle_client(ssl);
        }
    }
}

int server(SSL_CONNECTION_CONTEXT context)
{
    struct sockaddr_in client_addr;
    SSL_CTX *ctx = NULL;
    SSL* ssl = NULL;
    int port_num, listen_fd;
    int client_fd;
    pthread_t thread_pool[THREAD_POOL_SIZE];

    /* Parse the port number, and then validate it's range */
    port_num = atoi(context.port_string);
    if (port_num < 1 || port_num > 65535)
    {
        fprintf(stderr, "Invalid port number: %s\n", context.port_string);
        return -1;
    }

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Get a server context for our use */
    if (!(ctx = get_server_context(context.ca_pem, context.cert_pem, context.key_pem)))
    {
        return -1;
    }

    /* Get a socket which is ready to listen on the server's port number */
    if ((listen_fd = get_socket(port_num)) < 0)
    {
        goto fail;
    }

    for (int i = 0; i < THREAD_POOL_SIZE; i++)
    {
        pthread_create(&thread_pool[i], NULL, thread_function, NULL);
    }


    /* Get to work */
    while (true)
    {
        socklen_t client_addr_len = sizeof(client_addr);
        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0)
        {
            printf("Error accepting incoming connection: %s\n", strerror(errno));
            continue;
        }

        printf("New Connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        create_connection_log(client_addr);

        if (!(ssl = SSL_new(ctx)))
        {
            printf("Error creating SSL object for client\n");
            continue;
        }

        if (SSL_set_fd(ssl, client_fd) != 1)
        {
            printf("Error aatching ssl object to client socket.\n");
            SSL_free(ssl);

            continue;
        }

        if (SSL_accept(ssl) <= 0)
        {
            printf("Error performing ssl handshake: %s\n", ERR_error_string(ERR_get_error(), NULL));
            SSL_free(ssl);
            continue;
        }

        pthread_mutex_lock(&mutex);
        enqueue(ssl);
        pthread_cond_signal(&condition_var);
        pthread_mutex_unlock(&mutex);

    }
    /* Close the listening socket */
    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;

fail:
    SSL_CTX_free(ctx);
    return 1;
}

void saveLog(LOG_CONTEXT log, int response)
{
    log.userId = LOGIN_USER_ID;
    char current_time[VALID_INPUT_SIZE];
    get_local_time(current_time);
    strncpy(log.ipAddress, client.address, (int)sizeof(log.ipAddress));
    strncpy(log.time, current_time, (int)sizeof(log.time));

    if (strncmp(log.activity, "login", 5) == 0)
    {
        if (response <= 0)
        {
            strncpy(log.status, "FAIL", (int)sizeof(log.status));
        }
        else
        {
            strncpy(log.status, "SUCCESS", (int)sizeof(log.status));
        }
        addLog(log);
        return;
    }

    switch(response)
    {
    case SUCCESS:
        strncpy(log.status, "SUCCESS", (int)sizeof(log.status));
        break;
    case INVALID_HIERARCHY_AUTHORIZATION_MESSAGE:
        strncpy(log.status, "INVALID_HIERARCHY_AUTHORIZATION_MESSAGE", (int)sizeof(log.status));
        break;
    case INVALID_AUTHORIZATION_MESSAGE:
        strncpy(log.status, "INVALID_AUTHORIZATION_MESSAGE", (int)sizeof(log.status));
        break;
    case INVALID_OBJECT_MESSAGE:
        printf(log.status, "INVALID_OBJECT_MESSAGE", (int)sizeof(log.status));
        break;
    case DUPLICATE_VALUE_MESSAGE:
        strncpy(log.status, "DUPLICATE_VALUE_MESSAGE", (int)sizeof(log.status));
        break;
    case INVALID_DEVICE:
        strncpy(log.status, "INVALID_DEVICE", (int)sizeof(log.status));
        break;
    default:
        strncpy(log.status, "GENERIC_ERROR", (int)sizeof(log.status));
        break;
    }
    addLog(log);
}

void update_logout()
{
    struct LOG_CONTEXT log;
    strncpy(log.activity, "logout", (int)sizeof(log.activity));
    saveLog(log, 0);
}

int write_ssl_request_response(SSL* ssl, char* name, int status)
{
    struct LOG_CONTEXT log;
    struct SSL_RESPONSE response;
    int length = (int)strlen(name);
    int ssl_response = 0;
    if (length > VALID_INPUT_SIZE)
    {
        printf("Given name cause to buffer overflow.\n");
        return 1;
    }
    strncpy(response.activity, name, (int)sizeof(response.activity));
    response.status = status;
    ssl_response = SSL_write(ssl, &response, (int)sizeof(struct SSL_RESPONSE));
    strncpy(log.activity, name, (int)sizeof(log.activity));
    saveLog(log, status);
    ssl_status(ssl, ssl_response);
    activity_log(ssl, name, status);
    return 0;
}

void home_page(SSL *ssl)
{
    int router = 0;
    ssl_integer_receive(ssl, &router);
    printf("Router Point : %d\n", router);
    switch(router)
    {
    case 1:
        printf("Register Page\n");
        register_user(ssl);
        break;
    case 2:
        printf("Login Page\n");
        login_user(ssl, 1);
        break;
    case 3:
    	 activity_log(ssl, "LOGOUT", 0);
        update_logout();
        break;
    default:
        home_page(ssl);
    }
}

void register_user(SSL* ssl)
{
    int register_response = 0;
    int ssl_respone = 0;
    struct USER_CONTEXT user;

    ssl_respone = SSL_read(ssl, &user, (int)sizeof(struct USER_CONTEXT));
    ssl_status(ssl, ssl_respone);
    register_response = registerUser(user);
    write_ssl_request_response(ssl, USER_REGISTER, register_response);
    ssl_integer_receive(ssl, &register_response); // user register_response as a router.
    if (register_response == 1)
    {
    	activity_log(ssl, "REGISTER USER", 0);
        login_user(ssl, 1);
    }
    else
    {
    	activity_log(ssl, "REGISTER USER", 1);
        home_page(ssl);
    }
}

void login_user(SSL *ssl, int login_status)
{
    int router = 0;
    int login_response = -1;
    int ssl_response = 0;
    struct LOGIN_CONTEXT login_data;
    while (login_response < 0) // login page pops up till sucessfull login.
    {
    	if (login_status == 0) {break;}
        ssl_response = SSL_read(ssl, &login_data, (int)sizeof(struct LOGIN_CONTEXT));
        ssl_status(ssl, ssl_response);
        login_response = loginUser(login_data);
        LOGIN_USER_ID = login_response;
        printf("Login response : %d\n", login_response);
        write_ssl_request_response(ssl, USER_LOGIN, login_response);
        activity_log(ssl, "LOGIN USER", 1);

    }
    activity_log(ssl, "LOGIN USER", 0);
    ssl_integer_receive(ssl, &router); // router to go back / TPM page.
    printf("Received signal after login : %d\n", router);
    switch(router)
    {
    case 1:
        tpm_server(ssl, 0);
        break;
    case 2:
        logger_page(ssl);
        break;
    case 3:
        home_page(ssl);
        break;
    default:
        home_page(ssl); // If input is out of range it will go back to home page.
    }
}

void change_auth(SSL *ssl)
{
    int function_response = 0;
    int auth_type = 0;
    int ssl_response = 0;
    struct AUTH_CONTEXT auth;
    ssl_integer_receive(ssl, &auth_type);
    ssl_response = SSL_read(ssl, &auth, (int)sizeof(struct AUTH_CONTEXT));
    ssl_status(ssl, ssl_response);
    printf("Type : %d\n", auth_type);
    function_response = setAuthHierarchy(esys_context, auth_type, auth.old_auth, auth.new_auth);
    printf("Functional response : %d\n", function_response);
    write_ssl_request_response(ssl, CHANGE_AUTH, function_response);
    configure_tpm(ssl);
}

void configure_tpm(SSL *ssl)
{
    int router = 0;
    ssl_integer_receive(ssl, &router);
    switch(router)
    {
    case 1:
        clear_tpm(ssl); // To clear all privilleged credentials and keys from the TPM storage.
        break;
    case 2:
        change_auth(ssl);
        break;
    case 3:
        tpm_server(ssl, 1);
        break;
    default:
        configure_tpm(ssl);
    }
}

void seal_data(SSL *ssl)
{
    struct SEAL_CONTEXT seal;
    int seal_response = 0;
    int ssl_response = 0;
    ssl_response = SSL_read(ssl, &seal, (int)sizeof(struct SEAL_CONTEXT));
    ssl_status(ssl, ssl_response);
    seal_response = sealProxy(esys_context, seal);
    printf("Functional Response: %d\n", seal_response);
    write_ssl_request_response(ssl, ADD_KEY, seal_response);
    tpm_server(ssl, 1);
}

void unseal_data(SSL *ssl)
{
    struct SEAL_CONTEXT seal;
    int unseal_response = 0;
    int ssl_response = 0;
    ssl_response = SSL_read(ssl, &seal, (int)sizeof(struct SEAL_CONTEXT));
    ssl_status(ssl, ssl_response);
    unseal_response = unSealSecret(esys_context, seal);
    write_ssl_request_response(ssl, GET_KEY, unseal_response);
    tpm_server(ssl, 1);
}

void tpm_server(SSL *ssl, int flag)
{
    int router = 0;
    TSS2_RC response = TSS2_RC_SUCCESS;
    size_t device_size = 0;

    if (flag == 0)
    {
        /* response = Tss2_TctiLdr_Initialize(HOST_ADDRESS, &tcti_context); */
        response = Tss2_Tcti_Device_Init(tcti_context, &device_size, HOST_ADDRESS);
        if (response == TSS2_RC_SUCCESS)
        {
            printf("Simulator connection established...\n");
        }
        else
        {
            printf("Can't connect to the simulator...\n");
        }
        response = Esys_Initialize(&esys_context, tcti_context, NULL);
        if (response == TSS2_RC_SUCCESS)
        {
            printf("TPM Initialization Success...\n");
        }
        else
        {
            printf("Error in initializing...\n");
        }
    }

    ssl_integer_receive(ssl, &router);

    switch(router)
    {
    case 1:
        configure_tpm(ssl);
        break;
    case 2:
        seal_data(ssl);
        break;
    case 3:
        unseal_data(ssl);
        break;
    case 4:
        disk_encryption_page(ssl);
        break;
    case 5:
        home_page(ssl);
        break;
    default:
        tpm_server(ssl, 1);
    }
}

void disk_encryption_page(SSL *ssl)
{
    int router = 0;
    ssl_integer_receive(ssl, &router);
    switch(router)
    {
    case 1:
        if (add_disk_encryption_key(ssl) == 0)
        {
            encrypt_disk(ssl);
        }
        break;
    case 2:
        decrypt_disk(ssl);
        break;
    case 3:
        tpm_server(ssl, 1);
        break;
    default:
        disk_encryption_page(ssl);
    }

}

void encrypt_disk(SSL *ssl)
{
    char secret_data[KEY_SIZE];
    int ssl_response = 0;
    struct DISK_CONTEXT context;
    struct PERSISTED_CONTEXT seal;
    int encrypt_response = 0;
    ssl_response = SSL_read(ssl, &context, (int)sizeof(struct DISK_CONTEXT));
    ssl_status(ssl, ssl_response);

    strncpy(seal.indexName, context.key_file_name, (int)sizeof(seal.indexName));
    strncpy(seal.indexPassword, context.key_password, (int)sizeof(seal.indexPassword));
    encrypt_response = nvRead(esys_context, seal, secret_data);
    printf("secret data : %s\n", secret_data);
    ssl_integer_send(ssl, encrypt_response);
    if (encrypt_response != 0)
    {
        printf("No key exists with this name and password.\n");
    }
    else
    {
        secret_data[(int)strlen(secret_data)] = '\0';
        encrypt_response = format_disk(context.device_name, secret_data);
        write_ssl_request_response(ssl, ENCRYPT_DISK, encrypt_response);
    }

    disk_encryption_page(ssl);
}

void decrypt_disk(SSL *ssl)
{
    char secret_data[KEY_SIZE];
    int ssl_response = 0;
    struct DISK_CONTEXT context;
    struct PERSISTED_CONTEXT seal;
    int decrypt_response = 0;
    ssl_response = SSL_read(ssl, &context, (int)sizeof(struct DISK_CONTEXT));
    ssl_status(ssl, ssl_response);
    strncpy(seal.indexName, context.key_file_name, (int)sizeof(seal.indexName));
    strncpy(seal.indexPassword, context.key_password, (int)sizeof(seal.indexPassword));
    decrypt_response = nvRead(esys_context, seal, secret_data);
    ssl_integer_send(ssl, decrypt_response);
    if (decrypt_response != 0)
    {
        printf("Invalid key name / password\n");
    }
    else
    {
        decrypt_response = open_disk_by_passphrase(context.device_name, secret_data);

        write_ssl_request_response(ssl, OPEN_DISK, decrypt_response);
        /*if (decrypt_response == 0)
        {
        decrypt_response = close_disk(context.device_name); //For now once open the disk and do the activity we automatically closing it (changes will be added accordingly)
        }
        */
    }
    disk_encryption_page(ssl);
}

void clear_tpm(SSL *ssl)
{
    int ssl_response = 0;
    TSS2_RC result = 0;
    struct USER_CONTEXT user;

    ssl_response = SSL_read(ssl, &user, (int)sizeof(struct USER_CONTEXT));
    ssl_status(ssl, ssl_response);
    printf("Password : %s\n", user.userPassword);
    result = clearTpm(esys_context, user.userPassword); // data read from the client and performed TPM clear.
    printf("Clear TPM executed : %d\n", result);
    write_ssl_request_response(ssl, CLEAR_TPM, result); // response sending to client.
    configure_tpm(ssl);
}

int add_disk_encryption_key(SSL *ssl)
{
    struct PERSISTED_CONTEXT handle;
    int function_response = 0;
    int ssl_response = 0;
    ssl_response = SSL_read(ssl, &handle, (int)sizeof(struct PERSISTED_CONTEXT));
    ssl_status(ssl, ssl_response);
    printf("Key file Password : %s\n", handle.indexPassword);
    function_response = check_file_exists(handle.data);
    ssl_integer_send(ssl, function_response);
    if (function_response == 0)
    {
        printf("Invalid keyfile.\n");
    }
    else
    {
        function_response = nvProxy(esys_context, handle);
        write_ssl_request_response(ssl, ADD_KEY, function_response);
    }
    return function_response;
}

int get_disk_encryption_key(SSL *ssl, char*secret_data)
{
    struct PERSISTED_CONTEXT handle;
    int function_response = 0;
    int ssl_response = 0;
    ssl_response = SSL_read(ssl, &handle, (int)sizeof(PERSISTED_CONTEXT));
    ssl_status(ssl, ssl_response);
    function_response = nvRead(esys_context, handle, secret_data);
    write_ssl_request_response(ssl, GET_KEY, function_response);
    return function_response;
}

void logger_page(SSL *ssl)
{
    //printf("Logger Page.\n");
    int router = 0;
    ssl_integer_receive(ssl,&router);
    switch(router)
    {
        case 1:
            get_sys_event_log(ssl);
        break;
        case 2:
            get_app_log(ssl);
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
    int logger_response = 0;
    int ssl_response = 0;
    struct LOGGER_CONTEXT logger;

    ssl_response = SSL_read(ssl, &logger, (int)sizeof(struct LOGGER_CONTEXT));
    ssl_status(ssl, ssl_response);
    logger_response = send_log_to_server(logger.server_addr, logger.file_path);
    write_ssl_request_response(ssl, UPLOAD_LOG_TO_CLOUD, logger_response);
    logger_page(ssl);
}

void get_sys_event_log(SSL *ssl)
{
    int ssl_response = 0;
    int function_response = 0;
    struct LOGGER_CONTEXT logger;
    ssl_response = SSL_read(ssl,&logger,sizeof(struct LOGGER_CONTEXT));
    ssl_status(ssl,ssl_response);
    function_response = get_system_event_log(logger.file_path,logger.server_addr);
    write_ssl_request_response(ssl, WRITE_LOG_TO_JSON, function_response);
    logger_page(ssl);

}

void get_app_log(SSL *ssl)
{
     int ssl_response = 0;
     int function_response = 0;
     struct LOGGER_CONTEXT logger;
     ssl_response = SSL_read(ssl,&logger,sizeof(struct LOGGER_CONTEXT));
     ssl_status(ssl,ssl_response);
     function_response = get_application_log(logger.file_path,logger.server_addr);
     write_ssl_request_response(ssl, WRITE_LOG_TO_JSON, function_response);
     logger_page(ssl);
}

