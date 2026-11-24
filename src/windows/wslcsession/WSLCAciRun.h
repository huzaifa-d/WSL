// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#include "wslc.h"
#include "wslc_aci.h"
#include <atomic>
#include <thread>

namespace wsl::windows::service::wslc {

class WSLCAciRun
    : public Microsoft::WRL::RuntimeClass<Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>, IWSLCAciRun, IFastRundown, ISupportErrorInfo>
{
public:
    WSLCAciRun(IUnknown* Session, wil::shared_event Terminating);
    ~WSLCAciRun();

    void Initialize(_In_reads_bytes_(RequestSize) const byte* Request, ULONG RequestSize);
    IFACEMETHOD(GetStreams)(_Out_ WSLCHandle* Stdout, _Out_ WSLCHandle* Stderr) override;
    IFACEMETHOD(Wait)(_Out_ LONG* ExitCode) override;
    IFACEMETHOD(Cancel)() override;
    IFACEMETHOD(InterfaceSupportsErrorInfo)(_In_ REFIID Riid) override;

private:
    Microsoft::WRL::ComPtr<IUnknown> m_session;
    WslcAciRun* m_run{};
    wil::srwlock m_streamLock;
    _Guarded_by_(m_streamLock) wil::unique_handle m_stdout;
    _Guarded_by_(m_streamLock) wil::unique_handle m_stderr;
    wil::shared_event m_terminating;
    wil::unique_event m_stopMonitor{wil::EventOptions::ManualReset};
    std::thread m_monitor;
    std::atomic<bool> m_finished{};
};

} // namespace wsl::windows::service::wslc
