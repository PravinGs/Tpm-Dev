#include "adminservice.h"

void clearHandles()
{
    deleteAllFileHandles();
    deleteAllHandles();
    return;
}

TSS2_RC clearTpm(ESYS_CONTEXT* esys_context, const char* hierarchyAuth)
{
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};

    TPM2B_AUTH authValue =
    {
        .size = (UINT16)strlen(hierarchyAuth),
        .buffer = {0}
    };

    memcpy(authValue.buffer, hierarchyAuth, strlen(hierarchyAuth));
    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }
    response = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_LOCKOUT, &authValue); // Authentication check for using owner hierarchy.
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }

    response = Esys_Clear(esys_context, ESYS_TR_RH_LOCKOUT, session, ESYS_TR_NONE, ESYS_TR_NONE);

    if(response != TSS2_RC_SUCCESS)
    {
        printf("Error during TPM Clear...\n");
        goto error;
    }

    response = Esys_FlushContext(esys_context, session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to flush session.\n");
        goto error;
    }

    clearHandles();
    return response;
error :
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    return response;
}

TSS2_RC setAuthHierarchy(ESYS_CONTEXT* esys_context, int type, const char* oldAuthValue, const char* newAuthValue)
{
    TSS2_RC response = TSS2_RC_SUCCESS;
    ESYS_TR typeHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmteric = {.algorithm = TPM2_ALG_NULL};
    switch(type)
    {
    case 1:
        typeHandle = ESYS_TR_RH_OWNER;
        break;
    case 2:
        typeHandle = ESYS_TR_RH_PLATFORM;
        break;
    case 3:
        typeHandle = ESYS_TR_RH_ENDORSEMENT;
        break;
    case 4:
        typeHandle = ESYS_TR_RH_LOCKOUT;
        break;
    default:
        typeHandle = ESYS_TR_RH_OWNER;
    }

    TPM2B_AUTH oldPasword =
    {
        .size = (UINT16)strlen(oldAuthValue),
        .buffer = {0}
    };

    memcpy(oldPasword.buffer, oldAuthValue, strlen(oldAuthValue));

    TPM2B_AUTH newPassword =
    {
        .size = (UINT16)strlen(newAuthValue),
        .buffer = {0}
    };

    memcpy(newPassword.buffer, newAuthValue, strlen(newAuthValue));

    response = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmteric, TPM2_ALG_SHA256, &session);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to start auth session.\n");
        goto error;
    }
    response = Esys_TR_SetAuth(esys_context, typeHandle, &oldPasword);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to set auth value.\n");
        goto error;
    }
    response = Esys_HierarchyChangeAuth(esys_context,
                                        typeHandle,
                                        session,
                                        ESYS_TR_NONE,
                                        ESYS_TR_NONE,
                                        &newPassword);
    if (response != TSS2_RC_SUCCESS)
    {
        printf("Error at changing the password..\n");
        goto error;
    }
    response = Esys_FlushContext(esys_context, session);

    if (response != TSS2_RC_SUCCESS)
    {
        printf("Failed to flush the session context.\n");
        goto error;
    }

    return response;

error:
    if (session != ESYS_TR_NONE && Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS)
    {
        printf("Failed to clear session context.\n");
    }
    return response;
}
