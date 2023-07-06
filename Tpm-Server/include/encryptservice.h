#ifndef ENCRYPTSERVICE_H
#define ENCRYPTSERVICE_H
#include "keyservice.h"

TSS2_RC rsaEncryption(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal, int index, const char *filePath);
TSS2_RC rsaDecryption(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);
TSS2_RC removeEncryptionKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);
TSS2_RC swapEncryptionKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);
TSS2_RC encryptProxy(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);

#endif
