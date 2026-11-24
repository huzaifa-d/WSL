// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "Common.h"
#include "WslcAciClient.h"
#include "wslutil.h"
#include <array>
#include <atomic>
#include <mutex>
#include <thread>

namespace WSLCAciTests {

class FakeAciRun : public Microsoft::WRL::RuntimeClass<Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>, IWSLCAciRun>
{
public:
    explicit FakeAciRun(bool WaitForCancel, bool FailWait = false) : m_waitForCancel(WaitForCancel), m_failWait(FailWait)
    {
        auto [stdoutRead, stdoutWrite] = wsl::windows::common::wslutil::OpenAnonymousPipe(4096, false, false);
        auto [stderrRead, stderrWrite] = wsl::windows::common::wslutil::OpenAnonymousPipe(4096, false, false);
        m_stdout.reset(stdoutRead.release());
        m_stderr.reset(stderrRead.release());

        constexpr std::array<unsigned char, 4> output{0, 0xff, 0x80, '\n'};
        constexpr std::array<unsigned char, 3> errors{'e', 'r', 'r'};
        DWORD written{};
        THROW_IF_WIN32_BOOL_FALSE(WriteFile(stdoutWrite.get(), output.data(), static_cast<DWORD>(output.size()), &written, nullptr));
        THROW_HR_IF(E_FAIL, written != output.size());
        THROW_IF_WIN32_BOOL_FALSE(WriteFile(stderrWrite.get(), errors.data(), static_cast<DWORD>(errors.size()), &written, nullptr));
        THROW_HR_IF(E_FAIL, written != errors.size());
        if (m_failWait)
        {
            m_stdoutWriter.reset(stdoutWrite.release());
            m_stderrWriter.reset(stderrWrite.release());
        }
    }

    IFACEMETHOD(GetStreams)(WSLCHandle* Stdout, WSLCHandle* Stderr) override
    try
    {
        RETURN_HR_IF_NULL(E_POINTER, Stdout);
        RETURN_HR_IF_NULL(E_POINTER, Stderr);
        auto out = wsl::windows::common::wslutil::ToCOMOutputHandle(m_stdout.get(), GENERIC_READ | SYNCHRONIZE, WSLCHandleTypePipe);
        wil::unique_handle outGuard{out.Handle.Pipe};
        auto err = wsl::windows::common::wslutil::ToCOMOutputHandle(m_stderr.get(), GENERIC_READ | SYNCHRONIZE, WSLCHandleTypePipe);
        wil::unique_handle errGuard{err.Handle.Pipe};
        *Stdout = out;
        *Stderr = err;
        outGuard.release();
        errGuard.release();
        return S_OK;
    }
    CATCH_RETURN()

    IFACEMETHOD(Wait)(LONG* ExitCode) override
    {
        RETURN_HR_IF_NULL(E_POINTER, ExitCode);
        if (m_failWait)
        {
            return E_FAIL;
        }
        if (m_waitForCancel)
        {
            RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_TIMEOUT), WaitForSingleObject(m_cancelled.get(), 5000) != WAIT_OBJECT_0);
        }

        *ExitCode = 7;
        return S_OK;
    }

    IFACEMETHOD(Cancel)() override
    {
        ++m_cancelCount;
        ReleaseWriters();
        m_cancelled.SetEvent();
        return S_OK;
    }

    int CancelCount() const
    {
        return m_cancelCount.load();
    }

    HANDLE CancelEvent() const
    {
        return m_cancelled.get();
    }

    void ReleaseWriters()
    {
        std::lock_guard lock(m_writerLock);
        m_stdoutWriter.reset();
        m_stderrWriter.reset();
    }

private:
    bool m_waitForCancel;
    bool m_failWait;
    wil::unique_handle m_stdout;
    wil::unique_handle m_stderr;
    wil::unique_handle m_stdoutWriter;
    wil::unique_handle m_stderrWriter;
    std::mutex m_writerLock;
    wil::unique_event m_cancelled{wil::EventOptions::ManualReset};
    std::atomic<int> m_cancelCount{};
};

class WSLCAciTests
{
    WSL_TEST_CLASS(WSLCAciTests)

    TEST_METHOD(ForwardsBothStreamsAndExitCode)
    {
        auto run = Microsoft::WRL::Make<FakeAciRun>(false);
        VERIFY_IS_NOT_NULL(run.Get());
        auto [stdoutRead, stdoutWrite] = wsl::windows::common::wslutil::OpenAnonymousPipe(4096, false, false);
        auto [stderrRead, stderrWrite] = wsl::windows::common::wslutil::OpenAnonymousPipe(4096, false, false);

        const auto code = wsl::windows::common::wslc::ForwardAciRun(*run.Get(), stdoutWrite.get(), stderrWrite.get());
        VERIFY_ARE_EQUAL(7, code);
        stdoutWrite.reset();
        stderrWrite.reset();

        std::array<unsigned char, 8> buffer{};
        DWORD read{};
        VERIFY_WIN32_BOOL_SUCCEEDED(ReadFile(stdoutRead.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr));
        VERIFY_ARE_EQUAL(4u, read);
        VERIFY_ARE_EQUAL(0u, static_cast<unsigned>(buffer[0]));
        VERIFY_ARE_EQUAL(255u, static_cast<unsigned>(buffer[1]));
        VERIFY_ARE_EQUAL(128u, static_cast<unsigned>(buffer[2]));
        VERIFY_ARE_EQUAL(static_cast<unsigned>('\n'), static_cast<unsigned>(buffer[3]));

        VERIFY_WIN32_BOOL_SUCCEEDED(ReadFile(stderrRead.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr));
        VERIFY_ARE_EQUAL(3u, read);
        VERIFY_ARE_EQUAL(static_cast<unsigned>('e'), static_cast<unsigned>(buffer[0]));
        VERIFY_ARE_EQUAL(static_cast<unsigned>('r'), static_cast<unsigned>(buffer[1]));
        VERIFY_ARE_EQUAL(static_cast<unsigned>('r'), static_cast<unsigned>(buffer[2]));
    }

    TEST_METHOD(OutputFailureCancelsTheOperation)
    {
        auto run = Microsoft::WRL::Make<FakeAciRun>(true);
        VERIFY_IS_NOT_NULL(run.Get());
        wil::unique_event notAFile{wil::EventOptions::ManualReset};
        auto [stderrRead, stderrWrite] = wsl::windows::common::wslutil::OpenAnonymousPipe(4096, false, false);

        VERIFY_THROWS(wsl::windows::common::wslc::ForwardAciRun(*run.Get(), notAFile.get(), stderrWrite.get()), wil::ResultException);
        VERIFY_ARE_EQUAL(1, run->CancelCount());
    }

    TEST_METHOD(WaitFailureCancelsBeforeJoiningStreams)
    {
        auto run = Microsoft::WRL::Make<FakeAciRun>(false, true);
        VERIFY_IS_NOT_NULL(run.Get());
        auto [stdoutRead, stdoutWrite] = wsl::windows::common::wslutil::OpenAnonymousPipe(4096, false, false);
        auto [stderrRead, stderrWrite] = wsl::windows::common::wslutil::OpenAnonymousPipe(4096, false, false);
        std::thread safety{[run]() {
            if (WaitForSingleObject(run->CancelEvent(), 5000) == WAIT_TIMEOUT)
            {
                run->ReleaseWriters();
            }
        }};
        auto joinSafety = wil::scope_exit([&]() { safety.join(); });

        VERIFY_THROWS(wsl::windows::common::wslc::ForwardAciRun(*run.Get(), stdoutWrite.get(), stderrWrite.get()), wil::ResultException);
        VERIFY_ARE_EQUAL(1, run->CancelCount());
    }
};

} // namespace WSLCAciTests
