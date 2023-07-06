#include "client-api.h"
#define LINE_LENGTH 1024
#define CONFIG_FILE_PATH "config/client.config"

void signal_handler()
{
    printf("Handling the exit signal.\n");
    //handle server .
    exit(0);
}

static SSL_CONNECTION_CONTEXT get_ssl_context()
{
    FILE * file = NULL;
    SSL_CONNECTION_CONTEXT context;
    int index = 0;
    file = fopen(CONFIG_FILE_PATH, "rb");
    const char names[4][8] = {{'c', 'a'}, {'p', 'u', 'b', 'l', 'i', 'c'}, {'p', 'r', 'i', 'v', 'a', 't', 'e'}, {'i','p','p', 'o', 'r', 't'}};
    char line[LINE_LENGTH];
    if (file == NULL)
    {
    	fprintf(stderr, "Configuration file not exist.\n");
    	exit(1);
    }

    while (fgets(line, sizeof(line), file) != NULL || index < 4)
    {
        char * name = NULL;
        char * verify_name = NULL;
        char * value = NULL;
        char * token = NULL;

        token = strtok(line, "=");
        name  = token;
        token = strtok(NULL, "=");
        value = token;
        verify_name = malloc(sizeof(names[index]));
        strcpy(verify_name, names[index]);

        if (strncmp(name, verify_name, strlen(name)) != 0)
        {
           fprintf(stderr, "Incorrect Configuration file.\n");
           free(verify_name);
           exit(1);
        }
        else
        {
            switch (index)
            {
                case 0:
                strncpy(context.ca_pem, value, PATH_SIZE);
                if (context.ca_pem[strlen(context.ca_pem)-1] == '\n')
                {
                    context.ca_pem[strlen(context.ca_pem)-1] = '\0';
                }
                break;
                case 1:
                strncpy(context.cert_pem, value, PATH_SIZE);
                if (context.cert_pem[strlen(context.cert_pem)-1] == '\n')
                {
                    context.cert_pem[strlen(context.cert_pem)-1] = '\0';
                }
                break;
                case 2:
                strncpy(context.key_pem, value, PATH_SIZE);
                if (context.key_pem[strlen(context.key_pem)-1] == '\n')
                {
                    context.key_pem[strlen(context.key_pem)-1] = '\0';
                }
                break;
                case 3:
                strncpy(context.conn_string, value, PATH_SIZE);
                if (context.conn_string[strlen(context.conn_string)-1] == '\n')
                {
                    context.conn_string[strlen(context.conn_string)-1] = '\0';
                }
                break;
            }
        }
        index++;
        free(verify_name);

    }
    return context;
}


int main()
{
    signal(SIGINT, signal_handler);   
    struct SSL_CONNECTION_CONTEXT ssl_context = get_ssl_context();
    //strcpy(ssl_context.conn_string, CONN_STRING);
    //strcpy(ssl_context.ca_pem, CA_PEM);
    //strcpy(ssl_context.cert_pem, CERT_PEM);
    //strcpy(ssl_context.key_pem, KEY_PEM);
    client(ssl_context);
    return 0;
}
