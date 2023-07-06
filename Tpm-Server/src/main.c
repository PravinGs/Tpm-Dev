#include "server_api.h"

#define CONFIG_FILE_NAME "/home/pravin/projects/devrep/Tpm-Server/config/server.config"
#define LINE_LENGTH 1024

void signal_handler()
{
    printf("Handling the exit signal.\n");
    shutdown_server();
    exit(0);
}


static SSL_CONNECTION_CONTEXT get_ssl_context()
{
    FILE * file = NULL;
    SSL_CONNECTION_CONTEXT context;
    int index = 0;
    const char names[4][8] = {{'c', 'a'}, {'p', 'u', 'b', 'l', 'i', 'c'}, {'p', 'r', 'i', 'v', 'a', 't', 'e'}, {'p', 'o', 'r', 't'}};
    char line[LINE_LENGTH];

    file = fopen(CONFIG_FILE_NAME, "rb");
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
                strncpy(context.port_string, value, PATH_SIZE);
                if (context.port_string[strlen(context.port_string)-1] == '\n')
                {
                    context.port_string[strlen(context.port_string)-1] = '\0';
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
    struct SSL_CONNECTION_CONTEXT context = get_ssl_context();
    printf("%s\n", context.ca_pem);
/*    strcpy(context.port_string, PORT);
    strcpy(context.ca_pem, CA_PEM);
    strcpy(context.cert_pem, CERT_PEM);
    strcpy(context.key_pem, KEY_PEM);*/
    //openlog("tls-server", LOG_PID|LOG_CONS, LOG_USER);
    server(context);
    //closelog();
    return 0;
}
