// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#include "wslc.h"
#include <filesystem>

namespace wsl::windows::common::wslc {

int RunAciConfig(const std::filesystem::path& Config, HANDLE CancelEvent = nullptr, IWarningCallback* WarningCallback = nullptr, LPCWSTR SessionName = nullptr);
int ForwardAciRun(IWSLCAciRun& Run, HANDLE Stdout, HANDLE Stderr, HANDLE CancelEvent = nullptr);

} // namespace wsl::windows::common::wslc
