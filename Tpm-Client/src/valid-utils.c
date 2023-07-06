#include "valid-utils.h"

void get_number(int *number)
{
    printf("Enter an integer: ");
    char c;
    while(scanf("%d", number) == 0)
    {
        printf("Invalid input. Please enter an integer:");
        while ((c = getchar()) != '\n' && c != EOF) {}
    }
    getchar();
    return;
}

void get_string(char *string_, int string_len)
{
    char input[string_len + 1];
    char c;
    fgets(input, string_len, stdin);
    size_t len = strlen(input);
    if (input[len-1] != '\n')
    {
        printf("You have exceeded the given length of %d.\n", string_len);
        while ((c = getchar()) != '\n' && c != EOF) {}
        printf("Enter valid input:");
        get_string(string_, string_len);
    }
    if (len > 0 && input[len - 1] == '\n')
    {
        input[len - 1] = '\0';
        strcpy(string_, input);
    }
    return;
}

void get_user_password(char *string_, int string_len)
{
    char c;
    char password[string_len + 1];
    int i = 0;
    //printf("Enter password: ");
#ifdef _WIN32 // Windows-specific
    while (i < string_len)
    {
        char c = getch();
        if (c == '\r' || c == '\n' || c == EOF)
        {
            break; // Exit loop on Enter key or end of file
        }
        else if (c == '\b')
        {
            if (i > 0)
            {
                i--;
                printf("\b \b"); // Backspace to erase character
            }
        }
        else if (c >= 32 && c <= 126)
        {
            password[i] = c;
            i++;
            //printf("*"); // Print asterisk instead of character
        }
    }
#else // UNIX-specific
    struct termios term, term_orig;
    tcgetattr(STDIN_FILENO, &term);
    term_orig = term;
    term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL); // Turn off echoing
    tcsetattr(STDIN_FILENO, TCSANOW, &term);

    while (i < string_len)
    {
        char c = getchar();
        if (c == '\n' || c == EOF)
        {
            break; // Exit loop on Enter key or end of file
        }
        else if (c == '\b')
        {
            if (i > 0)
            {
                i--;
                printf("\b \b"); // Backspace to erase character
            }
        }
        else if (c >= 32 && c <= 126)
        {
            password[i] = c;
            i++;
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &term_orig); // Restore original terminal settings
#endif
    password[i] = '\0';
    if (i >= string_len)
    {
        password[string_len] = '\0';
        while ((c = getchar()) != '\n' && c != EOF) {}
    }
    strcpy(string_, password);
    printf("\n");
    return;
}

void get_password(char *password, int length)
{
    char password1[length];
    char password2[length];
    get_string(password1, length);
    printf("Enter password again to confirm: ");
    get_user_password(password2, length);
    while (strncmp(password1, password2, strlen(password1)) != 0)
    {
        printf("Please enter valid password try again\n");
        get_user_password(password2, length);
    }
    strcpy(password, password1);
}

void get_ip_and_port(char *conn_str, int length)
{
    printf("Enter Address ip:port: ");
    get_string(conn_str, length);
    return;
}

/*void get_ssl_context(SSL_CONNECTION_CONTEXT *context)
{
    printf("Enter Address ip:port: ");
    get_string(context->conn_string, PATH_SIZE);
    printf("Enter Certificate Authority(ca.pem) file: ");
    get_string(context->ca_pem, PATH_SIZE);
    printf("Enter Public Certificate(cert.pem) file: ");
    get_string(context->cert_pem, PATH_SIZE);
    printf("Enter Private Certificate(key.pem) file: ");
    get_string(context->key_pem, PATH_SIZE);
    return;
}*/

int ssl_integer_send(SSL *ssl, int value)
{
    uint32_t network_value = htonl((uint32_t) value);
    //printf("Network Value : %d\n", network_value);
    int result = 0;
    result = SSL_write(ssl, &network_value, (int)sizeof(network_value));
    if (result <= 0)
    {
        int error = SSL_get_error(ssl, result);
        switch (error)
        {
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL connection closed by peer\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf("The SSL connection is in non-blocking mode and requires more space in the read buffer" \
                   "before the write operation can be completed.");
            break;
        case SSL_ERROR_WANT_WRITE:
            /* Handle non-blocking I/O */
            printf("The SSL connection is in non-blocking mode and requires more space in the write buffer" \
                   "before the write operation can be completed.");
            break;
        case SSL_ERROR_SYSCALL:
            printf("Fatal error in underlying transport protocol\n");
            break;
        case SSL_ERROR_SSL:
            printf("Fatal error in SSL library\n");
            break;
        default:
            printf("Unknown SSL error\n");
        }
    }
    else
    {
        return 1;
    }
    return 1;
}

int ssl_integer_receive(SSL *ssl, int* value)
{
    int network_value = 0;
    int result = SSL_read(ssl, &network_value, (int)sizeof(network_value));
    //printf("Network Value : %d\n", network_value);
    if (result <= 0)
    {
        int error = SSL_get_error(ssl, result);
        switch (error)
        {
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL connection closed by peer\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf("The SSL connection is in non-blocking mode and requires more space in the read buffer" \
                   "before the write operation can be completed.");
            break;
        case SSL_ERROR_WANT_WRITE:
            /* Handle non-blocking I/O */
            printf("The SSL connection is in non-blocking mode and requires more space in the write buffer" \
                   "before the write operation can be completed.");
            break;
        case SSL_ERROR_SYSCALL:
            printf("Fatal error in underlying transport protocol\n");
            break;
        case SSL_ERROR_SSL:
            printf("Fatal error in SSL library\n");
            break;
        default:
            printf("Unknown SSL error\n");
        }
    }
    else
    {
        network_value = ntohl(network_value);
        *value = network_value;
        return 1;
    }
    return 0;
}

void ssl_status(SSL *ssl, int result)
{
    if (result <= 0)
    {
        int error = SSL_get_error(ssl, result);
        switch (error)
        {
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL connection closed by peer\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf("The SSL connection is in non-blocking mode and requires more space in the read buffer" \
                   "before the write operation can be completed.");
            break;
        case SSL_ERROR_WANT_WRITE:
            /* Handle non-blocking I/O */
            printf("The SSL connection is in non-blocking mode and requires more space in the write buffer" \
                   "before the write operation can be completed.");
            break;
        case SSL_ERROR_SYSCALL:
            printf("Fatal error in underlying transport protocol\n");
            break;
        case SSL_ERROR_SSL:
            printf("Fatal error in SSL library\n");
            break;
        default:
            printf("Unknown SSL error\n");
        }
    }
}

int read_ssl_request_response(SSL *ssl)
{
    struct SSL_RESPONSE ssl_response;
    int flag = 0;
    flag = SSL_read(ssl, &ssl_response, (int)sizeof(struct SSL_RESPONSE));
    ssl_status(ssl, flag);
    printf("Activity : %s\n", ssl_response.activity);
    printf("Status   : %d\n", ssl_response.status);
    if (strncmp(ssl_response.activity, "login", 5) == 0)
    {
        return ssl_response.status;
    }
    switch(ssl_response.status)
    {
    case SUCCESS:
        printf("Message  : SUCCESS\n");
        break;
    case INVALID_HIERARCHY_AUTHORIZATION_MESSAGE:
        printf("Message  : INVALID_HIERARCHY_AUTHORIZATION_MESSAGE\n");
        break;
    case INVALID_AUTHORIZATION_MESSAGE:
        printf("Message  : INVALID_AUTHORIZATION_MESSAGE\n");
        break;
    case INVALID_OBJECT_MESSAGE:
        printf("Message  : INVALID_OBJECT_MESSAGE\n");
        break;
    case DUPLICATE_VALUE_MESSAGE:
        printf("Message  : DUPLICATE_VALUE_MESSAGE\n");
        break;
    case INVALID_DEVICE:
        printf("Message  : INVALID_DEVICE\n");
        break;
    default:
        printf("Message  : GENERIC_ERROR\n");
        break;
    }
    return ssl_response.status;
}
