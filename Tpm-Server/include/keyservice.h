#ifndef KEYSERVICE_H
#define KEYSERVICE_H

/* TSS2 ESAPI & SIMULATOR LIBRARIES */

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>
/* STANDARD LIBRARIES */

#include <stdio.h>
#include <string.h>
#include "dbservice.h"

#define HOST_ADDRESS "/dev/tpm0"
#define RESPONSE_SIZE 50
#define BUFFER_SIZE 328
#define PCR_INDEX_SIZE 8
#define SEAL_DATA_SIZE 2046


typedef struct SEAL_CONTEXT SEAL_CONTEXT;
typedef struct PCR_CONTEXT PCR_CONTEXT;

struct SEAL_CONTEXT
{
    char ownerAuth[PASSWORD_SIZE];
    char srkAuth[PASSWORD_SIZE];
    char dekAuth[PASSWORD_SIZE];
    char data[DATA_SIZE];
    char objectName[PASSWORD_SIZE];
};

struct PCR_CONTEXT
{
    char data[DATA_SIZE];
    int hashIndex;
    int index[PCR_INDEX_SIZE];
};

TSS2_RC createSRK(ESYS_CONTEXT *esys_context,  SEAL_CONTEXT seal, const char* path, TPM2_HANDLE permanentHandle);

TSS2_RC createDEK(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal, const char*path, ESYS_TR srk_context, TPM2_HANDLE permanentHandle);

TSS2_RC createRsaSRK(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal, const char *filePath, TPM2_HANDLE permanentHandle);

TSS2_RC createNVAttestKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);

TSS2_RC deleteEncryptionKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);

TSS2_RC createaRsaDEK(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);

TSS2_RC deleteSealKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);



#endif
