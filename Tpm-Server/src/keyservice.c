#include "keyservice.h"

TSS2_RC createSRK(ESYS_CONTEXT *esys_context,  SEAL_CONTEXT seal, const char* path, TPM2_HANDLE permanentHandle)
{
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;


    TPM2B_SENSITIVE_CREATE inSensitive =
    {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = (UINT16)strlen(seal.srkAuth),
                .buffer = {0}
                ,
            },
            .data = {
                .size = 0,
                .buffer = {0}
            }
        }
    };

    memcpy(inSensitive.sensitive.userAuth.buffer, seal.srkAuth, strlen(seal.srkAuth));

    TPM2B_PUBLIC inPublic =
    {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES, // option to change it later
                    .keyBits.aes = 128, // option to change it later
                    .mode.aes = TPM2_ALG_CFB, // option to change it later
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL, // option to change it later [TPM2_ALG_NULL] for sealing data into it.
                },
                .keyBits = 2048, // option to change it later
                .exponent = 0,
            },
            .unique.rsa = { //additional hash if u wish to give to generate parent handle.
                .size = 0,
                .buffer = {0}
                ,
            }
        }
    };

    TPM2B_DATA outsideInfo =
    {
        .size = 0,
        .buffer = {0}
        ,
    };

    TPML_PCR_SELECTION creationPCR =
    {
        .count = 0,
    };

    TPM2B_AUTH authValue =
    {
        .size = (UINT16)strlen(seal.ownerAuth),
        .buffer = {0}
    };
    memcpy(authValue.buffer, seal.ownerAuth, strlen(seal.ownerAuth));

    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }

    response = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue); // Authentication check for using owner hierarchy.

    if (response != TSS2_RC_SUCCESS)
    {
        printf("ERROR : Authentication failure\n");
        goto error;
    }

    response = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                                  ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublic,
                                  &outsideInfo, &creationPCR, &objectHandle,
                                  &outPublic, &creationData, &creationHash,
                                  &creationTicket);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("ERROR : Creating Primary key\n");
        goto error;
    }

    response = Esys_FlushContext(esys_context, session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("ERROR during flush session context.\n");
        goto error;
    }

    response = createDEK(esys_context, seal, path, objectHandle, permanentHandle);
    if (response != TSS2_RC_SUCCESS)
    {
        goto error;
    }

    response = Esys_FlushContext(esys_context, objectHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("ERROR during flush object context\n");
        goto error;
    }

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    return response;
error:
    if (objectHandle != ESYS_TR_NONE && Esys_FlushContext(esys_context, objectHandle) != TSS2_RC_SUCCESS)
    {
        printf("Clearing object handle failed...\n");

    }
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    return response;
}

TSS2_RC createDEK(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal, const char*path, ESYS_TR srk_context, TPM2_HANDLE permanent_handle)
{
    struct PERSISTED_CONTEXT handle;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
    ESYS_TR persistent_handle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};
    TSS2_RC response = TSS2_RC_SUCCESS;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_PRIVATE *outPrivate = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TPM2B_SENSITIVE_DATA *outData = NULL;
    size_t buffer_size;
    uint8_t *buffer = NULL;
    uint8_t key_buffer[SEAL_DATA_SIZE];
    size_t key_buffe_size;
    FILE *file = NULL;

    file = fopen(seal.data, "rb");
    if (file == NULL)
    {
        printf("Invalid file name.\n");
        goto error;
    }

    key_buffe_size = fread(key_buffer, sizeof(uint8_t), sizeof(key_buffer), file);
    fclose(file);

    printf("Seal key size is : %zu\n", key_buffe_size);

    TPM2B_SENSITIVE_CREATE inSensitive =
    {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = (UINT16)strlen(seal.dekAuth),
                .buffer = {0}
                ,
            },
            .data = {
                .size =  (UINT16)key_buffe_size,
                .buffer = {0}
            }
        }
    };

    memcpy(inSensitive.sensitive.userAuth.buffer, seal.dekAuth, strlen(seal.dekAuth));
    memcpy(inSensitive.sensitive.data.buffer, key_buffer, key_buffe_size);

    TPM2B_PUBLIC inPublic =
    {
        .size = 0,
        .publicArea = {
            /* type = TPM2_ALG_RSA, */
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT
            ),

            .authPolicy = {
                .size = 0,
            },
            .parameters.keyedHashDetail = {
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {
                        .hmac = {
                            .hashAlg = TPM2_ALG_SHA256
                        }
                    }
                }
            },
            .unique.keyedHash = {
                .size = 0,
                .buffer = {0},
            },
        }
    };

    TPM2B_DATA outsideInfo =
    {
        .size = 0,
        .buffer = {0}
        ,
    };

    TPML_PCR_SELECTION creationPCR =
    {
        .count = 0,
    };

    TPM2B_AUTH primaryAuth =
    {
        .size = (UINT16)strlen(seal.srkAuth),
        .buffer = {0},
    };

    memcpy(primaryAuth.buffer, seal.srkAuth, strlen(seal.srkAuth));

    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }

    response = Esys_Create(esys_context,
                           srk_context,
                           session, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitive,
                           &inPublic,
                           &outsideInfo,
                           &creationPCR,
                           &outPrivate,
                           &outPublic,
                           &creationData, &creationHash, &creationTicket);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Error creating DEK\n");
        goto error;
    }

    response = Esys_Load(esys_context,
                         srk_context,
                         session,
                         ESYS_TR_NONE,
                         ESYS_TR_NONE, outPrivate, outPublic, &loadedKeyHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Error load key into the TPM\n");
        goto error;
    }

    response = Esys_EvictControl(esys_context, ESYS_TR_RH_OWNER, loadedKeyHandle,
                                 session, ESYS_TR_NONE, ESYS_TR_NONE,
                                 permanent_handle, &persistent_handle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to persist the seal key.\n");
        goto error;
    }

    response = Esys_TR_Serialize(esys_context, persistent_handle, &buffer, &buffer_size);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Error serializing DEK handle.\n");
        goto error;
    }

    file = fopen(path, "wb");

    if (file == NULL)
    {
        printf("No such file to write DEK handle.\n");
        goto error;
    }
    else
    {
        fwrite(buffer, sizeof(unsigned char), buffer_size, file);

        fclose(file);
    }

    char *indexName = malloc(strlen(seal.objectName) + 1);
    strcpy(indexName, seal.objectName);
    strcpy(handle.indexName, indexName);
    handle.indexValue = (int)permanent_handle;
    handle.dataSize = (int)key_buffe_size;
    strcpy(handle.indexPassword, seal.dekAuth);

    bool flag = updateNVIndex(handle);
    free(indexName);

    if (flag)
    {
        printf("DEK updated into Data base.\n");
    }

    response = Esys_FlushContext(esys_context, session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to flush session.\n");
        goto error;
    }


    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(outData);
    printf("Child key created.\n");
    return response;
error:
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(outData);
    printf("child key creation error.\n");
    return response;
}

TSS2_RC createRsaSRK(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal, const char *filePath, TPM2_HANDLE permanentHandle)
{

    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR persistent_handle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};
    FILE *file = NULL;
    size_t buffer_size;
    uint8_t *buffer = NULL;
    struct PERSISTED_CONTEXT handle;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TPM2B_AUTH authValuePrimary =
    {
        .size = (UINT16)strlen(seal.srkAuth),
        .buffer = {0}
    };
    memcpy(authValuePrimary.buffer, seal.srkAuth, strlen(seal.srkAuth));

    TPM2B_SENSITIVE_CREATE inSensitivePrimary =
    {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0},
            },
            .data = {
                .size = 0,
                .buffer = {0},
            },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic =
    {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL
                },
                .scheme = { .scheme = TPM2_ALG_RSAES },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {0},
            },
        },
    };


    TPM2B_DATA outsideInfo =
    {
        .size = 0,
        .buffer = {0},
    };

    TPML_PCR_SELECTION creationPCR =
    {
        .count = 0,
    };

    TPM2B_AUTH authValue =
    {
        .size = (UINT16)strlen(seal.ownerAuth),
        .buffer = {0}
    };
    memcpy(authValue.buffer, seal.ownerAuth, strlen(seal.ownerAuth));

    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }
    response = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    response = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                                  ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                                  &inPublic, &outsideInfo, &creationPCR,
                                  &objectHandle, &outPublic, &creationData,
                                  &creationHash, &creationTicket);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Error in Key gen\n");
        goto error;
    }

    response = Esys_EvictControl(esys_context, ESYS_TR_RH_OWNER, objectHandle,
                                 session, ESYS_TR_NONE, ESYS_TR_NONE,
                                 permanentHandle, &persistent_handle);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to persist encryption key.\n");
        goto error;
    }

    response = Esys_TR_Serialize(esys_context, persistent_handle, &buffer, &buffer_size);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to serialize encryption key.\n");
        goto error;
    }

    response = Esys_FlushContext(esys_context, session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to flush the session handle.\n");
        goto error;
    }

    handle.dataSize = (int)strlen(seal.data);
    handle.indexValue = permanentHandle;
    //handle.indexName = malloc(strlen(seal.objectName) + 1);
    //handle.indexPassword = malloc(strlen(seal.srkAuth) + 1);
    strcpy(handle.indexName, seal.objectName);
    strcpy(handle.indexPassword, seal.srkAuth);
    updateNVIndex(handle);


    file = fopen(filePath, "wb");

    if (file == NULL)
    {
        printf("No such file to write handle.\n");
        goto error;
    }
    else
    {
        fwrite(buffer, sizeof(uint8_t), buffer_size, file);

        fclose(file);
    }

    response = Esys_FlushContext(esys_context, objectHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Error flushing srk context\n");
        goto error;
    }

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    free(buffer);
    printf("Encryption key generated.\n");
    return response;
error :
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    if (objectHandle != ESYS_TR_NONE && Esys_FlushContext(esys_context, objectHandle) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear object context.\n");
    }

    if (buffer != NULL)
    {
        free(buffer);
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    return response;

}

TSS2_RC deleteEncryptionKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal)
{
    char filepath[20];
    char *destPath = NULL;
    UINT16 FAILIURE_RETURN = 1;
    const char LAST_NAME[] = ".cipher";


    PERSISTED_CONTEXT handle = existByIndexName(seal.objectName, seal.srkAuth);
    if (handle.indexValue == 0)
    {
        return FAILIURE_RETURN;
    }
    else
    {
        snprintf(filepath,sizeof(filepath), "%d", handle.indexValue);
    }
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};
    TPM2_HANDLE permanentHandle = TPM2_PERSISTENT_FIRST;

    FILE *file = NULL;
    uint8_t buffer[BUFFER_SIZE];
    size_t buffer_size;

    file = fopen(filepath, "rb");
    if (file == NULL)
    {
        printf("No such file to read from rsa srk handle.\n");
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
        printf("Failed to DE-serialize RSA SRK from delete encryption key.\n");
        goto error;
    }

    TPM2B_AUTH authValue =
    {
        .size = (UINT16)strlen(seal.ownerAuth),
        .buffer = {0}
    };
    memcpy(authValue.buffer, seal.ownerAuth, strlen(seal.ownerAuth));

    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }
    response = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }
    TPM2B_AUTH authSRK =
    {
        .size = (UINT16)strlen(seal.srkAuth),
        .buffer = {0}
    };

    memcpy(authSRK.buffer, seal.srkAuth, strlen(seal.srkAuth));

    response = Esys_TR_SetAuth(esys_context, objectHandle, &authSRK);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set object auth value.\n");
        goto error;
    }
    response = Esys_EvictControl(esys_context, ESYS_TR_RH_OWNER, objectHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, permanentHandle, &objectHandle);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to remove key from the TPM.\n");
        goto error;
    }

    response = Esys_FlushContext(esys_context, session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to flush session context.\n");
        goto error;
    }

    deleteHandle(seal.objectName, seal.srkAuth);
    remove(filepath);
    destPath = malloc(sizeof(filepath) + sizeof(LAST_NAME));
    strcpy(destPath, filepath);
    strcat(destPath, LAST_NAME);
    file = fopen(destPath, "rb");
    if (file == NULL)
    {
        free(destPath);
        goto error;
    }
    else
    {
        fclose(file);
        remove(destPath);
    }
    free(destPath);
    printf("Encryption key deleted from TPM.\n");
    return response;

error :

    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    return response;
}
