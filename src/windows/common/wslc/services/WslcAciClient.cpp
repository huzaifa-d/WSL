// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "WslcAciClient.h"
#include "WslcSessionManagerClient.h"
#include "ExecutionContext.h"
#include "WslSecurity.h"
#include "stringshared.h"
#include "wslc_aci.h"
#include "wslutil.h"
#include <atomic>
#include <thread>

using wsl::windows::common::io::HandleWrapper;
namespace wslc = wsl::windows::common::wslc;
namespace wslutil = wsl::windows::common::wslutil;

namespace {

#if defined(_M_X64)
struct BridgeBytes
{
    NON_COPYABLE(BridgeBytes);
    NON_MOVABLE(BridgeBytes);
    BridgeBytes() = default;

    ~BridgeBytes()
    {
        wslc_aci_free(Value);
    }

    WslcAciBytes Value{};

    std::string Message() const
    {
        if (Value.data == nullptr)
        {
            return "ACI request translation failed";
        }

        return {reinterpret_cast<const char*>(Value.data), Value.length};
    }
};

std::string ReadRequest(const std::filesystem::path& Path)
{
    wil::unique_hfile file{CreateFileW(
        Path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    THROW_LAST_ERROR_IF(!file);

    std::string result;
    std::array<char, 8192> buffer{};
    for (;;)
    {
        DWORD read{};
        THROW_IF_WIN32_BOOL_FALSE(ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr));
        if (read == 0)
        {
            return result;
        }
        result.append(buffer.data(), read);
    }
}
#endif

struct PumpState
{
    std::atomic<HRESULT> Failure{S_OK};
    wil::unique_event Failed{wil::EventOptions::ManualReset};

    void Report(HRESULT Result)
    {
        HRESULT expected = S_OK;
        Failure.compare_exchange_strong(expected, Result);
        Failed.SetEvent();
    }
};

void Pump(HandleWrapper Input, HANDLE Output, PumpState& State)
{
    const auto result = wil::ResultFromException([&]() {
        std::array<char, 8192> buffer{};
        for (;;)
        {
            DWORD read{};
            if (!ReadFile(Input.Get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
            {
                const auto error = GetLastError();
                if (error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF)
                {
                    return;
                }

                THROW_WIN32(error);
            }
            if (read == 0)
            {
                return;
            }

            DWORD offset{};
            while (offset < read)
            {
                DWORD written{};
                THROW_IF_WIN32_BOOL_FALSE(WriteFile(Output, buffer.data() + offset, read - offset, &written, nullptr));
                THROW_HR_IF(E_FAIL, written == 0);
                offset += written;
            }
        }
    });

    if (result != S_OK)
    {
        State.Report(result);
    }
}

void InterruptThread(std::thread& Thread)
{
    if (Thread.joinable() && !CancelSynchronousIo(Thread.native_handle()))
    {
        LOG_LAST_ERROR_IF(GetLastError() != ERROR_NOT_FOUND);
    }
}

} // namespace

int wslc::ForwardAciRun(IWSLCAciRun& Run, HANDLE Stdout, HANDLE Stderr, HANDLE CancelEvent)
{
    THROW_HR_IF(E_INVALIDARG, Stdout == nullptr || Stdout == INVALID_HANDLE_VALUE);
    THROW_HR_IF(E_INVALIDARG, Stderr == nullptr || Stderr == INVALID_HANDLE_VALUE);

    wslutil::COMOutputHandle stdoutHandle;
    wslutil::COMOutputHandle stderrHandle;
    THROW_IF_FAILED(Run.GetStreams(&stdoutHandle, &stderrHandle));
    auto stdoutPipe = stdoutHandle.Release();
    auto stderrPipe = stderrHandle.Release();

    wil::unique_event waitDone{wil::EventOptions::ManualReset};
    PumpState pumpState;
    HRESULT waitResult = E_FAIL;
    LONG exitCode{};
    std::wstring waitMessage;
    std::thread stdoutThread;
    std::thread stderrThread;
    std::thread waitThread;
    bool complete = false;
    auto cleanup = wil::scope_exit([&]() {
        if (!complete)
        {
            LOG_IF_FAILED(Run.Cancel());
            stdoutPipe.Reset();
            stderrPipe.Reset();
            InterruptThread(stdoutThread);
            InterruptThread(stderrThread);
        }
        if (stdoutThread.joinable())
        {
            stdoutThread.join();
        }
        if (stderrThread.joinable())
        {
            stderrThread.join();
        }
        if (waitThread.joinable())
        {
            waitThread.join();
        }
    });

    stdoutThread = std::thread{Pump, std::move(stdoutPipe), Stdout, std::ref(pumpState)};
    stderrThread = std::thread{Pump, std::move(stderrPipe), Stderr, std::ref(pumpState)};
    waitThread = std::thread{[&]() {
        waitResult = wil::ResultFromException([&]() {
            const auto coInit = wil::CoInitializeEx(COINIT_MULTITHREADED);
            const auto result = Run.Wait(&exitCode);
            if (result != S_OK)
            {
                if (auto info = wslutil::GetCOMErrorInfo(); info && info->Message)
                {
                    waitMessage = info->Message.get();
                }
            }
            THROW_IF_FAILED(result);
        });
        waitDone.SetEvent();
    }};

    std::array<HANDLE, 3> events{waitDone.get(), pumpState.Failed.get(), CancelEvent};
    const DWORD count = CancelEvent == nullptr ? 2 : 3;
    const auto wait = WaitForMultipleObjects(count, events.data(), FALSE, INFINITE);
    THROW_LAST_ERROR_IF(wait == WAIT_FAILED);
    THROW_HR_IF(E_UNEXPECTED, wait >= WAIT_OBJECT_0 + count);

    HRESULT cancelResult = S_OK;
    if (wait != WAIT_OBJECT_0)
    {
        cancelResult = Run.Cancel();
        THROW_LAST_ERROR_IF(WaitForSingleObject(waitDone.get(), INFINITE) == WAIT_FAILED);
    }
    waitThread.join();
    if (wait == WAIT_OBJECT_0 && waitResult != S_OK)
    {
        const auto cancellation = Run.Cancel();
        if (cancellation != S_OK)
        {
            InterruptThread(stdoutThread);
            InterruptThread(stderrThread);
        }
    }
    stdoutThread.join();
    stderrThread.join();
    complete = true;

    if (wait == WAIT_OBJECT_0 && waitResult != S_OK)
    {
        if (!waitMessage.empty())
        {
            THROW_HR_WITH_USER_ERROR(waitResult, waitMessage);
        }
        THROW_IF_FAILED(waitResult);
    }
    THROW_IF_FAILED(pumpState.Failure.load());
    THROW_IF_FAILED(cancelResult);
    if (waitResult != S_OK && !waitMessage.empty())
    {
        THROW_HR_WITH_USER_ERROR(waitResult, waitMessage);
    }
    THROW_IF_FAILED(waitResult);
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_CANCELLED), wait == WAIT_OBJECT_0 + 2);
    return exitCode;
}

int wslc::RunAciConfig(const std::filesystem::path& Config, HANDLE CancelEvent, IWarningCallback* WarningCallback, LPCWSTR SessionName)
{
#if defined(_M_X64)
    const auto json = ReadRequest(Config);
    BridgeBytes request;
    BridgeBytes error;
    if (wslc_aci_translate(reinterpret_cast<const unsigned char*>(json.data()), json.size(), &request.Value, &error.Value) != 0)
    {
        const auto message = error.Message();
        THROW_HR_WITH_USER_ERROR(E_INVALIDARG, wsl::shared::string::MultiByteToWide(message));
    }

    auto manager = CreateSessionManager();
    wil::com_ptr<IWSLCSession> session;
    if (SessionName != nullptr)
    {
        THROW_IF_FAILED(manager->OpenSessionByName(SessionName, &session));
    }
    else
    {
        THROW_IF_FAILED(manager->CreateSession(nullptr, WSLCSessionFlagsNone, WarningCallback, &session));
    }
    wsl::windows::common::security::ConfigureForCOMImpersonation(session.get());

    wil::com_ptr<IWSLCAciRun> run;
    const auto start = session->StartAciRun(gsl::narrow<ULONG>(request.Value.length), request.Value.data, &run);
    if (start != S_OK)
    {
        if (auto info = wslutil::GetCOMErrorInfo(); info && info->Message)
        {
            THROW_HR_WITH_USER_ERROR(start, info->Message.get());
        }
    }
    THROW_IF_FAILED(start);
    wsl::windows::common::security::ConfigureForCOMImpersonation(run.get());
    return ForwardAciRun(*run, GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE), CancelEvent);
#else
    UNREFERENCED_PARAMETER(Config);
    UNREFERENCED_PARAMETER(CancelEvent);
    UNREFERENCED_PARAMETER(WarningCallback);
    UNREFERENCED_PARAMETER(SessionName);
    THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED), "ACI micro-VM execution is not available on this architecture");
#endif
}
