#ifndef LOG_UTILITY_H
#define LOG_UTILITY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>

#define FAILIURE 0
#define LOG_DATA_LENGTH 1024
#define LOG_ID_SIZE 32
#define SYSTEM_LOG_PATH "/var/log/syslog"

int get_system_event_log(const char * log_path, const char * dest_path);
int get_application_log(const char * log_path, const char * dest_path);
int get_ufw_log();
int schedule_log_event();

int send_log_to_server(const char * server_addr, const char * file_path);



#endif
