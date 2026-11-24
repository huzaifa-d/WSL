// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "WslcSessionManagerClient.h"
#include "WslSecurity.h"

wil::com_ptr<IWSLCSessionManager> wsl::windows::common::wslc::CreateSessionManager()
{
    wil::com_ptr<IWSLCSessionManager> manager;
    THROW_IF_FAILED(CoCreateInstance(__uuidof(WSLCSessionManager), nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&manager)));
    wsl::windows::common::security::ConfigureForCOMImpersonation(manager.get());
    return manager;
}
