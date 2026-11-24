// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WslcAciBytes
{
    unsigned char* data;
    size_t length;
} WslcAciBytes;

int wslc_aci_translate(const unsigned char* json, size_t length, WslcAciBytes* request, WslcAciBytes* error);
void wslc_aci_free(WslcAciBytes buffer);

typedef struct WslcAciRun WslcAciRun;

int wslc_aci_start(
    const unsigned char* request,
    size_t request_length,
    const wchar_t* local_app_data,
    size_t local_app_data_length,
    WslcAciRun** run,
    void** stdout_read,
    void** stderr_read,
    WslcAciBytes* error);
int wslc_aci_wait(WslcAciRun* run, int* exit_code, WslcAciBytes* error);
int wslc_aci_cancel(WslcAciRun* run, WslcAciBytes* error);
int wslc_aci_release(WslcAciRun* run, WslcAciBytes* error);

#ifdef __cplusplus
}
#endif
