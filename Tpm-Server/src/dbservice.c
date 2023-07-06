#include "dbservice.h"

static sqlite3* db = NULL;

sqlite3* get_connection()
{
    if (db == NULL && sqlite3_open(DATABASE_PATH, &db) != SQLITE_OK)
    {
        printf("Invalid Database.\n");
    }
    else if (sqlite3_errcode(db) == SQLITE_MISUSE && sqlite3_open(DATABASE_PATH, &db) != SQLITE_OK)
    {
        printf("Invalid Database.\n");
    }
    return db;
}

void get_local_time(char *time_string)
{
    char current_time[NAME_SIZE];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(current_time, sizeof(current_time), "%Y-%m-%d %H:%M:%S", t);
    //printf("Current time : %s\n", current_time);
    strncpy(time_string, current_time, (int)sizeof(time_string));
    time_string[(int)strlen(current_time)] = '\0';
    return;
}

int registerUser(USER_CONTEXT user)
{
    int register_result = -1;
    sqlite3_stmt* stmt = NULL;
    sqlite3* connection = NULL;
    const char* QUERY = "INSERT INTO user_profile (user_name, user_email, user_password, user_role) VALUES (?,?,?,?);";
    int success = 0;
    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, user.userName, (int)strlen(user.userName), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, user.userEmail, (int)strlen(user.userEmail), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, user.userPassword, (int)strlen(user.userPassword), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, user.userRole, (int)strlen(user.userRole), SQLITE_STATIC);
            success = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (success != SQLITE_DONE)
            {
                printf("Register user operation failed.\n");
                goto error;
            }
            if (success == SQLITE_CONSTRAINT)
            {
                printf("User with this email already exists.\n");
                register_result = 2;
                goto error;
            }
        }
        else
        {
            goto error;
        }
    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    register_result = 1;
    return register_result;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return register_result;
}

int loginUser(LOGIN_CONTEXT credentials)
{
    int id = 0;
    sqlite3* connection = NULL;
    sqlite3_stmt* stmt = NULL;
    int success = 0;
    const char* QUERY = "SELECT user_id FROM user_profile WHERE user_email = ? and user_password = ?";

    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, credentials.userEmail, (int)strlen(credentials.userEmail), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, credentials.userPassword, (int)strlen(credentials.userPassword), SQLITE_STATIC);
            success = sqlite3_step(stmt);
            id = sqlite3_column_int(stmt,0);
            sqlite3_finalize(stmt);
            if (success != SQLITE_ROW)
            {
                printf("Invalid Credentials.\n");
                goto error;
            }
        }
        else
        {
            printf("Connection problem with DB or Invalid Query.\n");
            goto error;
        }
    }
    sqlite3_close(connection);
    return id;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return -1;

}

bool deleteUser(int userId)
{
    sqlite3* connection = NULL;
    sqlite3_stmt* stmt = NULL;
    const char* QUERY = "DELETE FROM user_profile WHERE user_id = ?";
    connection = get_connection();
    int result = 0;
    if (connection)
    {
        if ((int)sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_int(stmt, 1, userId);
            result = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (result == SQLITE_DONE)
            {
                printf("User Record removed successfully.\n");
            }
            else
            {
                goto error;
            }
        }
        else
        {
            printf("Other API Misuse");
            goto error;
        }
    }
    sqlite3_close(connection);
    return true;
error:
    if (connection)
    {
        sqlite3_close(connection);
    }
    return false;
}

bool addLog(LOG_CONTEXT log)
{
    sqlite3_stmt* stmt = NULL;
    sqlite3* connection = NULL;
    const char* QUERY = "INSERT INTO system_log (user_id, activity, log_time, ip_address, status) VALUES (?,?,?,?,?);";
    int result = 0;

    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_int(stmt, 1, log.userId);
            sqlite3_bind_text(stmt, 2, log.activity, (int)strlen(log.activity), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, log.time, (int)strlen(log.time), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, log.ipAddress, (int)strlen(log.ipAddress), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 5, log.status, (int)strlen(log.status), SQLITE_STATIC);
            result = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (result != SQLITE_DONE)
            {
                printf("Register user operation failed.\n");
                goto error;
            }
            if (result == SQLITE_CONSTRAINT)
            {
                printf("User with this email already exists.\n");
                goto error;
            }
        }
        else
        {
            goto error;
        }
    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    return true;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return false;
}

bool deleteHandle(const char * name, const char *password)
{
    sqlite3* connection = NULL;
    sqlite3_stmt* stmt = NULL;
    const char* QUERY = "DELETE FROM handles WHERE handle_name = ? and handle_password = ?";
    int result = 0;
    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, name, (int)strlen(name), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, password, (int)strlen(password), SQLITE_STATIC);
            result = sqlite3_step(stmt);
            if (result == SQLITE_DONE)
            {
                printf("Record removed.\n");
            }

            sqlite3_finalize(stmt);
        }
    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    return true;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return false;
}

bool deleteAllHandles()
{
    sqlite3* connection = NULL;
    sqlite3_stmt* stmt = NULL;
    const char* QUERY = "DELETE FROM handles";
    int result = 0;
    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            result = sqlite3_step(stmt);
            if (result == SQLITE_DONE)
            {
                printf("Handles removed successfully.\n");
            }
            else
            {
                goto error;
            }
        }
        else
        {
            goto error;
        }
    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    return true;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    else
    {
        printf("Connection closed.\n");
    }
    return false;
}

bool updateNVIndex(PERSISTED_CONTEXT handle)
{
    sqlite3_stmt* stmt = NULL;
    sqlite3* connection = NULL;
    const char* QUERY = "INSERT INTO handles (handle_name, handle_password, handle_index, data_size) VALUES (?,?,?,?);";
    int success = 0;
    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, handle.indexName, (int)strlen(handle.indexName), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, handle.indexPassword, (int)strlen(handle.indexPassword), SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, handle.indexValue);
            sqlite3_bind_int(stmt, 4, handle.dataSize);
            success = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (success != SQLITE_DONE)
            {
                printf("NV Handle creation failed.\n");
                goto error;
            }
        }
        else
        {
            goto error;
        }
    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    return true;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return false;
}

PERSISTED_CONTEXT existByIndexName(const char *name, const char *password)
{
    struct PERSISTED_CONTEXT handle;
    sqlite3_stmt* stmt = NULL;
    sqlite3* connection = NULL;
    const char* QUERY = "SELECT * FROM handles WHERE handle_name = ? and handle_password = ?";
    int success = 0;
    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, name, (int)strlen(name), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, password, (int)strlen(password), SQLITE_STATIC);
            success = sqlite3_step(stmt);
            if (success == SQLITE_ROW)
            {
                handle.indexValue = sqlite3_column_int(stmt, 3);
                handle.dataSize = sqlite3_column_int(stmt, 4);
                sqlite3_finalize(stmt);
            }
            else
            {
                goto error;
            }
        }
        else
        {
            goto error;
        }

    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    return handle;
error :
    handle.indexValue = 0;
    if (connection)
    {
        sqlite3_close(connection);
    }
    return handle;
}

bool existByIndex(int index)
{
    sqlite3_stmt* stmt = NULL;
    sqlite3* connection = NULL;
    const char* QUERY = "SELECT * FROM handles WHERE handle_index = ?";
    int success = 0;
    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_int(stmt, 1, index);
            success = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (success == SQLITE_ROW)
            {
                printf("Index already defined.\n");
            }
            else
            {
                printf("index not exists.\n");
                goto error;
            }
        }
        else
        {
            goto error;
        }
    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    return true;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return false;
}

void fileHelper(const char *path)
{
    FILE *file = NULL;
    file = fopen(path, "rb");
    const char DEST[] = ".cipher";
    if (file != NULL)
    {
        remove(path);
        fclose(file);
    }
    char *sub_path = malloc(strlen(path) + sizeof(DEST));
    strcpy(sub_path, path);
    strcat(sub_path, DEST);
    file = fopen(sub_path, "rb");
    if (file != NULL)
    {
        remove(sub_path);
        fclose(file);
    }
    free(sub_path);

}

bool deleteAllFileHandles()
{
    char path[25];
    sqlite3_stmt* stmt = NULL;
    sqlite3* connection = NULL;
    const char* QUERY = "SELECT handle_index FROM handles";
    int success = 0;
    connection = get_connection();
    if (connection == NULL)
    {
        printf("Connection not established\n");
        goto error;
    }
    if ((int)sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) != SQLITE_OK)
    {
        printf("Invalid Query.\n");
        goto error;
    }
    success = sqlite3_step(stmt);
    if (success == SQLITE_ROW)
    {
        while (sqlite3_column_int(stmt, 0))
        {
            int index = sqlite3_column_int(stmt, 0);
            snprintf(path, sizeof(path), "%d", index);
            fileHelper(path);
            sqlite3_step(stmt);
        }
    }
    else if (success == SQLITE_DONE)
    {
        printf("It is already in an updated state.\n");
    }
    else
    {
        printf("index not exist.\n");
        goto error;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(connection);
    return true;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return false;
}

bool isNameExist(const char *name)
{
    sqlite3_stmt* stmt = NULL;
    sqlite3* connection = NULL;
    const char* QUERY = "SELECT * FROM handles WHERE handle_name = ?";
    int success = 0;
    connection = get_connection();
    if (connection)
    {
        if (sqlite3_prepare_v2(connection, QUERY, strlen(QUERY), &stmt, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, name, (int)strlen(name), SQLITE_STATIC);
            success = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (success == SQLITE_ROW)
            {
                printf("Index already defined.\n");
            }
            else
            {
                printf("index not exists.\n");
                goto error;
            }
        }
        else
        {
            goto error;
        }
    }
    else
    {
        printf("Connection not established\n");
        goto error;
    }
    sqlite3_close(connection);
    return true;
error :
    if (connection)
    {
        sqlite3_close(connection);
    }
    return false;
}






