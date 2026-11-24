// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "WSLCAciRun.h"
#include "WSLCSession.h"
#include "WSLCExecutionContext.h"
#include "ExecutionContext.h"
#include "filesystem.hpp"
#include "stringshared.h"
#include "wslutil.h"

using wsl::windows::service::wslc::WSLCAciRun;
using wsl::windows::service::wslc::WSLCSession;

namespace {

#if defined(_M_X64)
struct BridgeError
{
    WslcAciBytes Value{};

    ~BridgeError()
    {
        wslc_aci_free(Value);
    }

    std::string Message() const
    {
        if (Value.data == nullptr)
        {
            return "ACI operation failed";
        }

        return {reinterpret_cast<const char*>(Value.data), Value.length};
    }
};
#endif

} // namespace

WSLCAciRun::WSLCAciRun(IUnknown* Session, wil::shared_event Terminating) :
    m_session(Session), m_terminating(std::move(Terminating))
{
}

WSLCAciRun::~WSLCAciRun()
{
    m_stopMonitor.SetEvent();
    if (m_monitor.joinable())
    {
        m_monitor.join();
    }
    m_stdout.reset();
    m_stderr.reset();
#if defined(_M_X64)
    if (m_run != nullptr)
    {
        BridgeError error;
        if (wslc_aci_release(m_run, &error.Value) != 0)
        {
            LOG_HR_MSG(E_FAIL, "ACI sandbox cleanup failed");
        }
    }
#endif
}

void WSLCAciRun::Initialize(const byte* Request, ULONG RequestSize)
{
#if defined(_M_X64)
    wil::unique_handle userToken;
    THROW_IF_WIN32_BOOL_FALSE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &userToken));
    // The Rust host opens and validates the directory components before using them.
    const auto localAppData = wsl::windows::common::filesystem::GetKnownFolderPath(
        FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY | KF_FLAG_NO_APPCONTAINER_REDIRECTION, userToken.get());
    const auto& path = localAppData.native();
    void* stdoutRead{};
    void* stderrRead{};
    BridgeError error;
    const int result = wslc_aci_start(Request, RequestSize, path.data(), path.size(), &m_run, &stdoutRead, &stderrRead, &error.Value);
    if (result != 0)
    {
        const auto message = error.Message();
        THROW_HR_WITH_USER_ERROR(E_FAIL, wsl::shared::string::MultiByteToWide(message));
    }

    m_stdout.reset(stdoutRead);
    m_stderr.reset(stderrRead);
    m_monitor = std::thread{[this]() {
        const HANDLE events[]{m_stopMonitor.get(), m_terminating.get()};
        const auto result = WaitForMultipleObjects(ARRAYSIZE(events), events, FALSE, INFINITE);
        if (result == WAIT_OBJECT_0 + 1 && !m_finished.load())
        {
            BridgeError error;
            if (wslc_aci_cancel(m_run, &error.Value) != 0)
            {
                LOG_HR_MSG(E_FAIL, "Cannot cancel ACI command during WSLC session termination");
            }
        }
        else
        {
            LOG_LAST_ERROR_IF(result == WAIT_FAILED);
        }
    }};
#else
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(RequestSize);
    THROW_HR(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED));
#endif
}

HRESULT WSLCAciRun::GetStreams(WSLCHandle* Stdout, WSLCHandle* Stderr)
try
{
    RETURN_HR_IF_NULL(E_POINTER, Stdout);
    RETURN_HR_IF_NULL(E_POINTER, Stderr);
    *Stdout = {};
    *Stderr = {};
    auto lock = m_streamLock.lock_exclusive();
    RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_STATE), !m_stdout || !m_stderr);

    auto stdoutHandle = wsl::windows::common::wslutil::ToCOMOutputHandle(m_stdout.get(), GENERIC_READ | SYNCHRONIZE, WSLCHandleTypePipe);
    wil::unique_handle stdoutGuard{stdoutHandle.Handle.Pipe};
    auto stderrHandle = wsl::windows::common::wslutil::ToCOMOutputHandle(m_stderr.get(), GENERIC_READ | SYNCHRONIZE, WSLCHandleTypePipe);
    wil::unique_handle stderrGuard{stderrHandle.Handle.Pipe};

    *Stdout = stdoutHandle;
    *Stderr = stderrHandle;
    stdoutGuard.release();
    stderrGuard.release();
    m_stdout.reset();
    m_stderr.reset();
    return S_OK;
}
CATCH_RETURN()

HRESULT WSLCAciRun::Wait(LONG* ExitCode)
try
{
    RETURN_HR_IF_NULL(E_POINTER, ExitCode);
    wsl::windows::common::COMServiceExecutionContext context;
#if defined(_M_X64)
    BridgeError error;
    int code{};
    const int result = wslc_aci_wait(m_run, &code, &error.Value);
    m_finished.store(true);
    if (result != 0)
    {
        const auto message = error.Message();
        THROW_HR_WITH_USER_ERROR(E_FAIL, wsl::shared::string::MultiByteToWide(message));
    }

    *ExitCode = code;
    return S_OK;
#else
    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
#endif
}
CATCH_RETURN()

HRESULT WSLCAciRun::Cancel()
try
{
    wsl::windows::common::COMServiceExecutionContext context;
#if defined(_M_X64)
    BridgeError error;
    if (wslc_aci_cancel(m_run, &error.Value) != 0)
    {
        const auto message = error.Message();
        THROW_HR_WITH_USER_ERROR(E_FAIL, wsl::shared::string::MultiByteToWide(message));
    }

    return S_OK;
#else
    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
#endif
}
CATCH_RETURN()

HRESULT WSLCAciRun::InterfaceSupportsErrorInfo(REFIID Riid)
{
    return Riid == __uuidof(IWSLCAciRun) ? S_OK : S_FALSE;
}

HRESULT WSLCSession::StartAciRun(ULONG RequestSize, const byte* Request, IWSLCAciRun** Run)
try
{
    RETURN_HR_IF_NULL(E_POINTER, Run);
    *Run = nullptr;
    RETURN_HR_IF_NULL(E_POINTER, Request);
    RETURN_HR_IF(E_INVALIDARG, RequestSize == 0);
    RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_STATE), m_terminating.load() || m_sessionTerminatedEvent.is_signaled());

    wsl::windows::service::wslc::WSLCExecutionContext context(this);
    auto operation = Microsoft::WRL::Make<WSLCAciRun>(static_cast<IWSLCSession*>(this), m_sessionTerminatingEvent);
    THROW_IF_NULL_ALLOC(operation.Get());
    operation->Initialize(Request, RequestSize);
    RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_STATE), m_terminating.load() || m_sessionTerminatedEvent.is_signaled());
    *Run = operation.Detach();
    return S_OK;
}
CATCH_RETURN()
