#include "log-api.h"
#include "map_d.h"

#define CONFIG_FILE "config/log.config"

static int get_json_names(Map* map)
{
    FILE * file = NULL;
    char line[LOG_DATA_LENGTH];

    file = fopen(CONFIG_FILE, "rb");
    if (file == NULL)
    {
    	fprintf(stderr, "Configuration file not exist.\n");
    	return 0; // Need to be updated
    }
    while (fgets(line, sizeof(line), file) != NULL)
    {
        char * token = NULL;
        char * name  = NULL;
        char * value = NULL;

        token = strtok(line, "=");
        name = token;
        token = strtok(NULL, "=");
        value = token;
        if (name[strlen(name)-1] == '\n')
        {
            name[strlen(name)-1] = '\0';
        }
        if (value[strlen(value)-1] == '\n')
        {
            value[strlen(value)-1] = '\0';
        }
        add_to_map(map, name, value);
    }
    return 1;
}


int get_system_event_log(const char * log_path, const char * dest_path)
{
    FILE * file = NULL;
    char log[LOG_DATA_LENGTH];
    char log_id[LOG_ID_SIZE];
    char *json_str = NULL;
    cJSON *json = NULL;
    cJSON *log_entry = NULL;
    cJSON *timestamp = NULL;
    cJSON *hostname = NULL;
    cJSON *program = NULL;
    cJSON *message = NULL;
    int log_count = 0;

    file = fopen(log_path, "rb");
    if (file == NULL)
    {
        printf("Error opening file %s\n", log_path);
        file = fopen(SYSTEM_LOG_PATH, "r"); /*Read the syslog file from the standard file location.*/
    }

    json = cJSON_CreateObject();

    while (fgets(log, sizeof(log), file) != NULL)
    {
        char *token = NULL;
        char *month = NULL;
        char *day   = NULL;
        char *time  = NULL;
        char *host  = NULL;
        char *prog  = NULL;
        char *msg   = NULL;
        char time_format[LOG_ID_SIZE];

        token = strtok(log, " ");
        month = token;
        token = strtok(NULL, " ");
        day = token;
        token = strtok(NULL, " ");
        time = token;
        token = strtok(NULL, " ");
        host = token;
        token = strtok(NULL, " ");
        prog = token;
        token = strtok(NULL, "");
        msg = token;

        // create JSON object for syslog entry
        log_entry = cJSON_CreateObject();

        // add parsed data as key-value pairs to the JSON object
        snprintf(time_format, LOG_ID_SIZE, "%s %s %s", month, day, time);
        timestamp = cJSON_CreateString(time_format);
        cJSON_AddItemToObject(log_entry, "timestamp", timestamp);

        hostname = cJSON_CreateString(host);
        cJSON_AddItemToObject(log_entry, "hostname", hostname);

        program = cJSON_CreateString(prog);
        cJSON_AddItemToObject(log_entry, "program", program);

        message = cJSON_CreateString(msg);
        cJSON_AddItemToObject(log_entry, "message", message);

        if (msg[(strlen(msg) - 1)] == '\n')
        {
            msg[( strlen(msg) - 1)] = '\0';
        }

        // add syslog entry to the JSON object
        snprintf(log_id, LOG_ID_SIZE, "log_%d", log_count);
        cJSON_AddItemToObject(json, log_id, log_entry);
        log_count++;
    }
    fclose(file);

    // save JSON object to file
    json_str = cJSON_Print(json);
    file = fopen(dest_path, "w");
    fputs(json_str, file);
    fclose(file);

    cJSON_Delete(json); //Free memory
    free(json_str);

    return 0;
}


int get_application_log(const char * log_path, const char * dest_path)
{
    Map map;
    map.size = 0;
    FILE * file = NULL;
    char log[LOG_DATA_LENGTH];
    char log_id[LOG_ID_SIZE];
    char * file_name = NULL;
    char * sep = NULL;
    int attributes_count = 0;
    char *json_str = NULL;
    cJSON *json = NULL;
    cJSON *log_entry = NULL;
    int log_count = 0;

    if (get_json_names(&map) == 0)
    {
        return 1;
    }

    file_name = get_from_map(&map, "path");
    sep = get_from_map(&map, "sep");
    attributes_count = get_count(&map);

    file = fopen(file_name, "rb");
    if (file == NULL)
    {
        printf("Error opening file %s\n", file_name);
        return 1;
    }

    json = cJSON_CreateObject();

    while (fgets(log, sizeof(log), file) != NULL)
    {
    	int index = 0;
        char *token = NULL;
        char *value = NULL;
        
        log_entry = cJSON_CreateObject();

        token = strtok(log, sep);
        value = token;
        cJSON_AddItemToObject(log_entry, get_value_by_index(&map, index, attributes_count), cJSON_CreateString(value));

        for (index = 1; index < attributes_count; index++)
        {
            char *child = NULL;
            token = strtok(NULL, sep);
            child = token;
            if (child[(strlen(child) - 1)] == '\n')
            {
                child[( strlen(child) - 1)] = '\0';
            }
            char * name = get_value_by_index(&map, index, attributes_count);
            cJSON_AddItemToObject(log_entry, name, cJSON_CreateString(child));
        }

        snprintf(log_id, LOG_ID_SIZE, "log_%d", log_count);
        cJSON_AddItemToObject(json, log_id, log_entry);
        log_count++;

    }
    fclose(file);

    json_str = cJSON_Print(json);
    file = fopen(dest_path, "w");
    fputs(json_str, file);
    fclose(file);

    cJSON_Delete(json); //Free memory
    free(json_str);

    return 0;
}



int schedule_log_event()
{
    pid_t pid;
    int status = 1;

    // Fork a new process toget_event_log run the crontab command
    pid = fork();
    if (pid == 0)
    {
        // Child process: execute the crontab command
        execl("/usr/bin/crontab", "crontab", "-", (char *) NULL);
        return FAILIURE;
    }
    else if (pid < 0)
    {
        // Error: unable to fork
        perror("fork");
        return FAILIURE;
    }

    // Parent process: write the crontab entry to standard output
    printf("0-15 17 * * * log.o\n");

    // Wait for the child process to complete
    waitpid(pid, &status, 0);
    return 1;
}

int send_log_to_server(const char * server_addr, const char * file_path)
{
    CURL *curl = NULL;
    CURLcode res;
    FILE *fp = NULL;
    struct stat sp;

    fp = fopen(file_path, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file\n");
        return 1;
    }
    int f = open(file_path, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fstat(f,&sp) == -1)
    {
        perror("couldn't get file.\n");
        return 1;
    }

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, server_addr);
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/ca.pem");
        curl_easy_setopt(curl, CURLOPT_SSLKEY, "/path/to/client.key");
        curl_easy_setopt(curl, CURLOPT_SSLCERT, "/path/to/client.crt");
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, fp);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)sp.st_size);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        curl_easy_cleanup(curl);
    }

    fclose(fp);
    return 0;
}
