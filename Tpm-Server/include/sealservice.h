#ifndef SEALSERVICE_H
#define SEALSERVICE_H
#include "keyservice.h"

TSS2_RC sealSecret(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal,int index, const char* path);
TSS2_RC unSealSecret(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);
TSS2_RC nvWrite(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal, int i, const char* path);
TSS2_RC nvRead(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal, char *secret_data);
TSS2_RC nvDelete(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal);
TSS2_RC nvDefineSpace(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal, int i, const char* path);
TSS2_RC nvProxy(ESYS_CONTEXT *esys_context, PERSISTED_CONTEXT seal);
TSS2_RC deleteSealKey(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);
TSS2_RC sealProxy(ESYS_CONTEXT *esys_context, SEAL_CONTEXT seal);

#endif
