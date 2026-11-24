// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#include "wslc.h"

namespace wsl::windows::common::wslc {

wil::com_ptr<IWSLCSessionManager> CreateSessionManager();

} // namespace wsl::windows::common::wslc
