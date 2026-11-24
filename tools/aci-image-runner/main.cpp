// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "ExecutionContext.h"
#include "Localization.h"
#include "WslTelemetry.h"
#include "WslcAciClient.h"
#include "wslutil.h"

int wmain(int argc, wchar_t const** argv)
{
    using namespace wsl::windows::common;

    EnableContextualizedErrors(false, true);
    wslutil::ConfigureCrt();
    wslutil::InitializeWil();
    WslTraceLoggingInitialize(WslcTelemetryProvider, !wsl::shared::OfficialBuild);
    auto cleanupTelemetry = wil::scope_exit_log(WI_DIAGNOSTICS_INFO, []() { WslTraceLoggingUninitialize(); });
    wslutil::SetCrtEncoding(_O_U8TEXT);
    ExecutionContext context(Context::WslC);

    try
    {
        if (argc != 3 || std::wstring_view{argv[1]} != L"--config" || argv[2][0] == L'\0' || std::wstring_view{argv[2]}.starts_with(L"--"))
        {
            std::fwprintf(stderr, L"%ls\n", wsl::shared::Localization::MessageAciRunnerUsage().c_str());
            return 1;
        }

        const auto coInit = wil::CoInitializeEx(COINIT_MULTITHREADED);
        wslutil::CoInitializeSecurity();
        return wsl::windows::common::wslc::RunAciConfig(argv[2]);
    }
    catch (...)
    {
        const auto result = wil::ResultFromCaughtException();
        const auto error = context.ReportedError().value_or(wsl::windows::common::Error{.Code = result});
        const auto strings = wslutil::ErrorToString(error);
        const auto& message = strings.Message.empty() ? strings.Code : strings.Message;
        std::fwprintf(stderr, L"aci-image-runner: %ls\n", message.c_str());
        return 1;
    }
}
