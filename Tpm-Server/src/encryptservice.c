#include "encryptservice.h"
const char *LAST_NAME = ".cipher";

TSS2_RC rsaEncryption(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal, int index, const char* filePath)
{
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};

    TPM2B_PUBLIC_KEY_RSA *cipher = NULL;
    FILE *file = NULL;
    uint8_t buffer[500];
    size_t buffer_size;

    TPM2B_AUTH auth =
    {
        .size = (UINT16)strlen(seal.srkAuth),
        .buffer = {0}
    };

    memcpy(auth.buffer, seal.srkAuth, strlen(seal.srkAuth));

    TPM2B_PUBLIC_KEY_RSA plain = {.size = (UINT16)strlen(seal.data),.buffer = {0}};

    memcpy(plain.buffer, seal.data, strlen(seal.data));

    TPMT_RSA_DECRYPT scheme;
    scheme.scheme = TPM2_ALG_RSAES;

    TPM2_HANDLE permanentHandle = TPM2_PERSISTENT_FIRST + index;

    response = createRsaSRK(esys_context, seal, filePath, permanentHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Error creating RSA Key\n");
        goto error;
    }

    file = fopen(filePath, "rb");

    if (file == NULL)
    {
        printf("No such file to read RSA SRK handle.\n");
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
        printf("Failed to DE-Serialize RSA SRK.\n");
        goto error;
    }
    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }
    response = Esys_TR_SetAuth(esys_context, objectHandle, &auth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }
    response = Esys_RSA_Encrypt(esys_context, objectHandle, ESYS_TR_NONE,
                                ESYS_TR_NONE, ESYS_TR_NONE, &plain, &scheme,
                                NULL, &cipher);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("RSA Encryption failed\n.");
        goto error;
    }

    response = Esys_FlushContext(esys_context, session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to flush session handle.\n");
        goto error;
    }
    char *dek_path = malloc(sizeof(LAST_NAME) + strlen(filePath));
    strcpy(dek_path,filePath);
    strcat(dek_path, LAST_NAME);
    printf("File path : %s\n", filePath);
    printf("DEK PATH : %s\n", dek_path);

    file = fopen(dek_path, "wb");


    if (file == NULL)
    {
        printf("No such file cipher to write encrypted blob.\n");
        free(dek_path);
        goto error;
    }
    else
    {
        fwrite(cipher->buffer, sizeof(uint8_t), cipher->size, file);
        fclose(file);
    }
    free(dek_path);
    Esys_Free(cipher);
    printf("RSA Encryption success.\n");
    return response;
error:
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    Esys_Free(cipher);
    return response;
}

TSS2_RC rsaDecryption(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{
    char path[30];
    PERSISTED_CONTEXT handle = existByIndexName(seal.objectName, seal.srkAuth);
    if (handle.indexValue == 0)
    {
        return 1;
    }
    else
    {
        snprintf(path, sizeof(path),"%d", handle.indexValue);
    }
    TSS2_RC response = TSS2_RC_SUCCESS;
    FILE *file = NULL;
    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};
    TPM2B_PUBLIC_KEY_RSA *plain = NULL;
    TPMT_RSA_DECRYPT scheme;
    scheme.scheme = TPM2_ALG_RSAES;
    uint8_t buffer[256];
    uint8_t loadedBuffer[500];
    size_t loadedBufferSize;
    uint16_t buffer_size;

    file = fopen(path, "rb");
    if (file == NULL)
    {
        printf("No such file to read the RSA - SRK handle for RSA-DECRYPTION.\n");
        goto error;
    }
    else
    {
        loadedBufferSize = fread(loadedBuffer, sizeof(uint8_t), sizeof(loadedBuffer), file);
        fclose(file);
    }
    char *filePath = malloc(sizeof(path) + sizeof(LAST_NAME));
    strcpy(filePath, path);
    printf("Cipher Path : %s\n", filePath);
    strcat(filePath, LAST_NAME);
    printf("Path for cipher handle : %s\n", path);
    file = fopen(filePath, "rb");
    if (file == NULL)
    {
        printf("No such file to read the encrypted block.\n");
        goto error;
    }
    else
    {
        buffer_size = fread(buffer, sizeof(uint8_t), (uint16_t)sizeof(buffer), file);
        fclose(file);
    }

    free(filePath);

    TPM2B_PUBLIC_KEY_RSA cipher =
    {
        .size = buffer_size,
        .buffer = {0}
    };
    memcpy(cipher.buffer, buffer, (uint16_t)buffer_size);

    response = Esys_TR_Deserialize(esys_context, loadedBuffer, loadedBufferSize, &objectHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to deserialize RSA-SRK for RSA-DECRYPTION.\n");
        goto error;
    }

    TPM2B_AUTH auth =
    {
        .size = (UINT16)strlen(seal.srkAuth),
        .buffer = {0}
    };
    memcpy(auth.buffer, seal.srkAuth, strlen(seal.srkAuth));

    TPM2B_AUTH oAuth =
    {
        .size = (UINT16)strlen(seal.ownerAuth),
        .buffer = {0}
    };
    memcpy(oAuth.buffer, seal.ownerAuth, strlen(seal.ownerAuth));
    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }
    response = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &oAuth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }
    response = Esys_TR_SetAuth(esys_context, objectHandle, &auth);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set object auth session.\n");
        goto error;
    }
    response = Esys_RSA_Decrypt(esys_context, objectHandle,
                                session, ESYS_TR_NONE, ESYS_TR_NONE,
                                &cipher, &scheme, NULL, &plain);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Decryption Failed.\n");
        goto error;
    }
    response = Esys_FlushContext(esys_context, session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("failed to flush session.\n");
        goto error;
    }
    printf("decrypted text : %s\n", plain->buffer);
    return response;
error :
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    printf("Error : Decrypting data.\n");
    free(filePath);
    return response;
}

TSS2_RC removeEncryptionKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{

    return deleteEncryptionKey(esys_context, seal);

}

TSS2_RC swapEncryptionKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{
    TSS2_RC response = TSS2_RC_SUCCESS;

    response = removeEncryptionKey(esys_context, seal);

    if (response != TSS2_RC_SUCCESS)
    {
        goto error;
    }

    return encryptProxy(esys_context, seal);

error:

    return response;
}

TSS2_RC encryptProxy(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{
    UINT16 failure_return = 1;
    char filename[20];
    int persistent = TPM2_PERSISTENT_FIRST;
    bool flag = false;
    int index = 0;
    if (isNameExist(seal.objectName) == true)
    {
        failure_return = 101;
        return failure_return;
    }

    while(index < 3)
    {
        flag = existByIndex(persistent + index);
        if (flag == false)
        {
            break;
        }
        index++;
    }

    if ((int)flag == 1 && index >= 3)
    {
        return failure_return;
    }
    else
    {
        persistent = persistent + index;
        snprintf(filename, sizeof(filename), "%d", persistent);
        printf("The created Path : %s\n", filename);
        return rsaEncryption(esys_context, seal, index, filename);
    }

}
