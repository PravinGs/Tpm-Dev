#include "sealservice.h"

TSS2_RC sealSecret(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal, int index, const char* path)
{
    TSS2_RC response = TSS2_RC_SUCCESS;

    TPM2_HANDLE permanentHandle = TPM2_PERSISTENT_FIRST + index;

    response = createSRK(esys_context, seal, path, permanentHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Primary key creation failed.\n");
        goto error;
    }

    return response;

error :
    printf("Failed to seal secret into TPM.\n");
    return response;
}

TSS2_RC unSealSecret(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{
    UINT16 FAILIURE_RETURN = 1;
    char path[20];
    PERSISTED_CONTEXT handle = existByIndexName(seal.objectName, seal.dekAuth);
    if (handle.indexValue == 0)
    {
        printf("no records available.\n");
        return FAILIURE_RETURN;
    }
    else
    {
        snprintf(path, sizeof(path), "%d", handle.indexValue);
    }
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};
    TPM2B_SENSITIVE_DATA *outData = NULL;
    FILE *file = NULL;
    uint8_t buffer[BUFFER_SIZE];
    size_t buffer_size;

    TPM2B_AUTH ownerAuth =
    {
        .size = (UINT16)strlen(seal.ownerAuth),
        .buffer = {0}
    };
    memcpy(ownerAuth.buffer, seal.ownerAuth, strlen(seal.ownerAuth));

    TPM2B_AUTH authValue =
    {
        .size = (UINT16)strlen(seal.dekAuth),
        .buffer = {0}
    };
    memcpy(authValue.buffer, seal.dekAuth, strlen(seal.dekAuth));

    file = fopen(path, "rb");

    if (file == NULL)
    {
        printf("No such file to read dek handle.\n");
        goto error;
    }
    else
    {
        buffer_size = fread(buffer, sizeof(uint8_t), sizeof(buffer), file);

        fclose(file);
    }

    response = Esys_TR_Deserialize(esys_context, buffer, buffer_size, &loadedKeyHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to deserialize dek handle.\n");
        goto error;
    }
    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }

    response = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &ownerAuth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }

    response = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authValue);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }
    response = Esys_Unseal(esys_context, loadedKeyHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, &outData);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("failed to unseal the secret.\n");
        goto error;
    }
    printf("Unsealed data : %s\n", outData->buffer);

    response = Esys_FlushContext(esys_context, session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("failed to flush session.\n");
        goto error;
    }
    Esys_Free(outData);
    return response;

error :
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    Esys_Free(outData);
    return response;
}

TSS2_RC nvWrite(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal, int i, const char* path)
{
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    FILE *file = NULL;
    uint8_t buffer[BUFFER_SIZE];
    uint8_t key_buffer[BUFFER_SIZE];
    size_t key_buffe_size;
    uint8_t *outBuffer = NULL;
    size_t buffer_size;
    UINT16 offset = 0;

    response = nvDefineSpace(esys_context, seal, i, path);

    if (response != TSS2_RC_SUCCESS)
    {
        goto error;
    }

    TPM2B_AUTH auth =
    {
        .size = (UINT16)strlen(seal.indexPassword),
        .buffer = {0}
    };

    memcpy(auth.buffer, seal.indexPassword, strlen(seal.indexPassword));

    file = fopen(seal.data, "rb");
    key_buffe_size = fread(key_buffer, sizeof(uint8_t), sizeof(key_buffer), file);
    fclose(file);
    printf("Key buffer size: %d\n", (int)key_buffe_size);
    key_buffer[key_buffe_size] = '\0';

    TPM2B_MAX_NV_BUFFER nv_test_data =
    {
        .size = (UINT16)key_buffe_size,
        .buffer = {0}
    };

    memcpy(nv_test_data.buffer, key_buffer, key_buffe_size);

    file = fopen(path, "rb");
    if (file == NULL)
    {
        printf("No such file to Read NV handle.\n");
        goto error;
    }
    else
    {
        buffer_size = fread(buffer, sizeof(uint8_t), sizeof(buffer), file);
        fclose(file);
    }

    response = Esys_TR_Deserialize(esys_context, buffer, buffer_size, &nvHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Deserialization failed in NV Write.\n");
        goto error;
    }

    response = Esys_TR_SetAuth(esys_context, nvHandle, &auth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }

    response = Esys_NV_Write(esys_context,
                             nvHandle,
                             nvHandle,
                             ESYS_TR_PASSWORD,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &nv_test_data,
                             offset);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to write data into NV RAM.\n");
        goto error;
    }

    response = Esys_TR_Serialize(esys_context, nvHandle, &outBuffer, &buffer_size);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to serialize nv handle.\n");
        goto error;
    }

    file = fopen(path, "wb");
    if (file == NULL)
    {
        goto error;
    }
    else
    {
        fwrite(outBuffer, sizeof(uint8_t), buffer_size, file);
        fclose(file);
    }
    bool dbResponse = false;
    seal.indexValue = TPM2_NV_INDEX_FIRST + i;
    seal.dataSize = (int)key_buffe_size;
    dbResponse = updateNVIndex(seal);
    if (dbResponse)
    {
        printf("Handle saved in DB.\n");
    }
    return response;
error :
    return response;
}

TSS2_RC nvRead(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal, char* secret_data)
{
    UINT16 FAILIURE_RETURN = 1;
    struct PERSISTED_CONTEXT persistedHandle;
    char path[10];
    persistedHandle = existByIndexName(seal.indexName, seal.indexPassword);
    if (persistedHandle.indexValue == 0)
    {
        return FAILIURE_RETURN;
    }
    else
    {
        snprintf(path, sizeof(path), "%d", persistedHandle.indexValue);
    }
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2B_MAX_NV_BUFFER *nv_test_data2 = NULL;
    uint8_t buffer[BUFFER_SIZE];
    FILE *file = NULL;
    size_t buffer_size;

    file = fopen(path, "rb");
    printf("PAth : %s\n", path);
    if (file == NULL)
    {
        printf("No such file to Read NV handle.\n");
        goto error;
    }
    else
    {
        buffer_size = fread(buffer, sizeof(uint8_t), sizeof(buffer), file);
        fclose(file);
    }

    response = Esys_TR_Deserialize(esys_context, buffer, buffer_size, &nvHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("DE-Serialization failed in NV Read.\n");
        goto error;
    }


    TPM2B_AUTH owner_auth =
    {
        .size = (UINT16)strlen(seal.ownerPassword),
        .buffer = {0}
    };

    memcpy(owner_auth.buffer, seal.ownerPassword, strlen(seal.ownerPassword));

    TPM2B_AUTH auth =
    {
        .size = (UINT16)strlen(seal.indexPassword),
        .buffer = {0}
    };

    memcpy(auth.buffer, seal.indexPassword, strlen(seal.indexPassword));

    response = Esys_TR_SetAuth(esys_context, nvHandle, &owner_auth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }

    response = Esys_TR_SetAuth(esys_context, nvHandle, &auth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }

    response = Esys_NV_Read(esys_context, nvHandle, nvHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, (UINT16)persistedHandle.dataSize, 0, &nv_test_data2);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to read data from NV RAM.\n");
        goto error;
    }

    printf("The data from NV RAM : %s\n", nv_test_data2->buffer);
    for (int i = 0; i < (int)nv_test_data2->size; i++)
    {
        if (nv_test_data2->buffer[i] == '\0')
        {
            break;
        }
        secret_data[i] = nv_test_data2->buffer[i];
    }

    secret_data[strlen(secret_data)] = '\0';

    Esys_Free(nv_test_data2);
    return response;

error :

    Esys_Free(nv_test_data2);
    return response;
}

TSS2_RC nvDelete(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal)
{
    UINT16 FAILIURE_RETURN = 1;

    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    bool flag = false;
    struct PERSISTED_CONTEXT persistedHandle;
    char path[10];
    persistedHandle = existByIndexName(seal.indexName, seal.indexPassword);
    if (persistedHandle.indexValue == 0)
    {
        return FAILIURE_RETURN;
    }
    else
    {
        snprintf(path, sizeof(path), "%d", persistedHandle.indexValue);
    }
    FILE *file = NULL;
    uint8_t buffer[BUFFER_SIZE];
    size_t buffer_size;

    TPM2B_AUTH owner_auth =
    {
        .size = (UINT16)strlen(seal.ownerPassword),
        .buffer = {0}
    };
    memcpy(owner_auth.buffer, seal.ownerPassword, strlen(seal.ownerPassword));

    TPM2B_AUTH auth =
    {
        .size = (UINT16)strlen(seal.indexPassword),
        .buffer = {0}
    };
    memcpy(auth.buffer, seal.indexPassword, strlen(seal.indexPassword));

    file = fopen(path, "rb");

    if (file == NULL)
    {
        printf("Invalid file path.\n");
        goto error;
    }

    else
    {
        buffer_size = fread(buffer, sizeof(uint8_t), sizeof(buffer), file);

        fclose(file);
    }

    response = Esys_TR_Deserialize(esys_context, buffer, buffer_size, &nvHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("NV DE-Serialization failed.\n");
        goto error;
    }

    response = Esys_TR_SetAuth(esys_context, nvHandle, &owner_auth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }


    response = Esys_TR_SetAuth(esys_context, nvHandle, &auth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }

    response = Esys_NV_UndefineSpace(esys_context, ESYS_TR_RH_OWNER, nvHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to delete index from NVRam.\n");
        goto error;
    }

    flag = deleteHandle(seal.indexName, seal.indexPassword);

    if (flag)
    {
        printf("Record removed from database.\n");
    }

    remove(path);
    return response;

error:

    return response;
}

TSS2_RC nvProxy(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal)
{
    UINT16 FAILIURE_RETURN = 1;

    char filename[10];
    int nvIndex = TPM2_NV_INDEX_FIRST;
    bool flag = false;
    int i = 0;
    if (isNameExist(seal.indexName) == true)
    {
        FAILIURE_RETURN = 101;
        return FAILIURE_RETURN;
    }
    while(i >= 0 && i < 3)
    {
        flag = existByIndex(nvIndex + i);
        if (flag == false)
        {
            break;
        }
        i++;
    }

    if ((int)flag == 1 && i >= 3)
    {
        return FAILIURE_RETURN;
    }
    nvIndex = nvIndex + i;
    snprintf(filename, sizeof(filename),"%d", nvIndex);
    printf("The created Path : %s\n", filename);
    return nvWrite(esys_context, seal, i, filename);
}

TSS2_RC nvDefineSpace(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal, int i, const char*path)
{
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    FILE *file = NULL;
    uint8_t*buffer = NULL;
    size_t buffer_size;
    printf("NV Password : %s\n", seal.indexPassword);
    printf("Owner Password : %s\n", seal.ownerPassword);

    TPM2B_AUTH owner_auth =
    {
    	.size = (UINT16)strlen(seal.ownerPassword),
    	.buffer = {0}
    };

    memcpy(owner_auth.buffer, seal.ownerPassword, strlen(seal.ownerPassword));

    TPM2B_AUTH auth =
    {
        .size = (UINT16)strlen(seal.indexPassword),
        .buffer = {0}
    };

    memcpy(auth.buffer, seal.indexPassword, strlen(seal.indexPassword));

    response = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &owner_auth);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }

    TPM2B_NV_PUBLIC publicInfo =
    {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST + i,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD
            ),
            .authPolicy = {
                .size = 0,
                .buffer = {0},
            },
            .dataSize = DATA_SIZE,
        }
    };

    response = Esys_NV_DefineSpace(esys_context,
                                   ESYS_TR_RH_OWNER,
                                   ESYS_TR_PASSWORD,
                                   ESYS_TR_NONE,
                                   ESYS_TR_NONE,
                                   &auth,
                                   &publicInfo,
                                   &nvHandle);

    if(response != TSS2_RC_SUCCESS)
    {
        printf("Failed to define space in NV Define\n");
        goto error;
    }

    response = Esys_TR_Serialize(esys_context, nvHandle, &buffer, &buffer_size);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to serialize the NV RAM data.\n");
        goto error;
    }

    file = fopen(path, "wb");

    if (file == NULL)
    {
        printf("No such file to write Nv handle.\n");
        goto error;
    }
    else
    {
        fwrite(buffer, sizeof(uint8_t), buffer_size, file);
        fclose(file);
    }
    return response;

error :
    return response;
}

TSS2_RC deleteSealKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{
    UINT16 FAILIURE_RETURN = 1;
    char filepath[20];
    const char DEK_KEY[] = "-dek-key";
    PERSISTED_CONTEXT handle = existByIndexName(seal.objectName, seal.srkAuth);
    if (handle.indexValue == 0)
    {
        return FAILIURE_RETURN;
    }
    else
    {
        snprintf(filepath, sizeof(filepath), "%d", handle.indexValue);
    }

    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};
    uint8_t buffer[400];
    FILE *file = NULL;
    size_t buffer_size;
    file = fopen(filepath, "rb");
    if (file == NULL)
    {
        goto error;
    }
    else
    {
        buffer_size = fread(buffer, sizeof(uint8_t), sizeof(buffer), file);
        fclose(file);
    }
    response = Esys_TR_Deserialize(esys_context, buffer, buffer_size, &objectHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to DE-Serialize the SRK handle in Seal key deletion.\n");
        goto error;
    }
    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }

    response = Esys_EvictControl(esys_context, ESYS_TR_RH_OWNER, objectHandle,
                                 session, ESYS_TR_NONE, ESYS_TR_NONE,
                                 handle.indexValue, &objectHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to evict the handle {%d}\n", handle.indexValue);
        goto error;
    }

    response = Esys_FlushContext(esys_context, session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("failed to flush session handle.\n");
        goto error;
    }

    if (!(deleteHandle(seal.objectName, seal.srkAuth)))
    {
        goto error;
    }
    remove(filepath);
    char *childObjectName = malloc(strlen(seal.objectName) + sizeof(DEK_KEY));
    strcpy(childObjectName, seal.objectName);
    strcat(childObjectName, DEK_KEY);
    printf("DEK key : %s\n", childObjectName);
    snprintf(filepath, sizeof(filepath),"%d", handle.indexValue+handle.dataSize);
    printf("The DEK file name : %s\n", childObjectName);
    if (!(deleteHandle(childObjectName, seal.dekAuth)))
    {
        free(childObjectName);
        goto error;
    }
    remove(filepath);
    free(childObjectName);

    return response;
error:
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    return response;
}

TSS2_RC sealProxy(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{
    UINT16 FAILIURE_RETURN = 1;
    char filename[20];
    int sealIndex = TPM2_PERSISTENT_FIRST;
    bool flag = false;
    int index = 0;
    if (isNameExist(seal.objectName) == true)
    {
        FAILIURE_RETURN = 101;
        return FAILIURE_RETURN;
    }
    while(index < 3)
    {
        flag = existByIndex(sealIndex + index);
        if (flag == false)
        {
            break;
        }
        index++;
    }

    if ((int)flag == 1 && index >= 3)
    {
        return FAILIURE_RETURN;
    }
    else
    {
        sealIndex = sealIndex + index;
        snprintf(filename, sizeof(filename),"%d", sealIndex);
        printf("The created Path : %s\n", filename);
        return sealSecret(esys_context, seal, index, filename);
    }

}
