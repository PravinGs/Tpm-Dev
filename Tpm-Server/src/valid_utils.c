#include "valid_utils.h"

#include "dbservice.h"


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

int ssl_integer_send(SSL *ssl, int value)
{
    uint32_t network_value = htonl((uint32_t) value);
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
        //printf("Bytes written to SSL connection successfully.\n");
        return 1;
    }
    return 0;
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
        //printf("Bytes read successfully.\n");
        return 1;
    }
    return 0;

}

int ssl_status(SSL *ssl, int result)
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
    else
    {
        //printf("SSL success.\n");
        return 1;
    }
    return 0;

}


int check_file_exists(const char* file_path)
{
    int response = 0;
    FILE *file = NULL;

    file = fopen(file_path, "rb");
    if (file != NULL)
    {
        response = 1;
        fclose(file);
    }

    return response;
}

int convert_key_bin(char *key, const uint8_t *hex, unsigned int size)
{
	char buffer[3];
	char *endp;
	unsigned int i;

	buffer[2] = '\0';

	for (i = 0; i < size; i++) {
		buffer[0] = *hex++;
		buffer[1] = *hex++;

		key[i] = (unsigned char)strtoul(buffer, &endp, 16);

		if (endp != &buffer[2])
			return -1;
	}

	if (*hex != '\0')
		return -1;

	return 0;
}

int is_device_valid(const char* device)
{
    int fd= open(device, O_RDWR);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    if (size == -1) {
        perror("lseek");
        close(fd);
        return -1;
    }
    printf("The size of the device : %ld\n", size);
    return 0;
}

void crypt_error_msg(int encryption_result, const char* error_message)
{
    printf("%s : %d\n", error_message, encryption_result);
}
