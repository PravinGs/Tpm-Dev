#ifndef USERSERVICE_H
#define USERSERVICE_H

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <regex.h>

#define DATABASE_PATH "/home/pravin/projects/devrep/Tpm-Server/src/secrets"
#define NAME_SIZE 20
#define PASSWORD_SIZE 20
#define USER_ROLE_SIZE 5
#define TIME_SIZE 20
#define DATA_SIZE 100

typedef struct USER_CONTEXT USER_CONTEXT;
typedef struct LOGIN_CONTEXT LOGIN_CONTEXT;
typedef struct LOG_CONTEXT LOG_CONTEXT;
typedef struct PERSISTED_CONTEXT PERSISTED_CONTEXT ;

struct USER_CONTEXT
{
    char userName[NAME_SIZE];
    char userEmail[NAME_SIZE];
    char userPassword[PASSWORD_SIZE];
    char userRole[USER_ROLE_SIZE];
};

struct LOGIN_CONTEXT
{
    char userEmail[NAME_SIZE];
    char userPassword[PASSWORD_SIZE];
};

struct LOG_CONTEXT
{
    int userId;
    char time[TIME_SIZE];
    char activity[TIME_SIZE];
    char status[DATA_SIZE];
    char ipAddress[NAME_SIZE];
};

struct PERSISTED_CONTEXT
{
    char indexName[PASSWORD_SIZE];
    char ownerPassword[PASSWORD_SIZE];
    char data[DATA_SIZE];
    int indexValue;
    char indexPassword[PASSWORD_SIZE];
    int dataSize;
};

sqlite3* get_connection();
int registerUser(USER_CONTEXT user);
int loginUser(LOGIN_CONTEXT credentials);
bool deleteUser(int userId);
bool addLog(LOG_CONTEXT log);
bool deleteHandle(const char * name, const char *password);
bool deleteAllHandles();
bool existByIndex(int index);
PERSISTED_CONTEXT existByIndexName(const char *name, const char *password);
bool updateNVIndex(PERSISTED_CONTEXT handle);
bool deleteAllFileHandles();
void fileHelper(const char *path);
bool isNameExist(const char *name);
void get_local_time(char *time_string);



#endif
