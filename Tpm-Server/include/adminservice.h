#ifndef ADMINSERVICE_H
#define ADMINSERVICE_H

#include "keyservice.h"

TSS2_RC clearTpm(ESYS_CONTEXT* esys_context, const char* hierarchyAuth);
TSS2_RC setAuthHierarchy(ESYS_CONTEXT* esys_context, int type, const char* oldAuthValue, const char* newAuthValue);
void clearHandles();

#endif
