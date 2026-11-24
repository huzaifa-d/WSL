// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "AciCommand.h"
#include "ArgumentConvertedTypes.h"
#include "CLIExecutionContext.h"
#include "WarningCallback.h"
#include "WslcAciClient.h"

using namespace wsl::windows::wslc::execution;
using namespace wsl::shared;

namespace wsl::windows::wslc {

std::vector<Argument> AciRunCommand::GetArguments() const
{
    return {Argument::Create(ArgType::AciConfig, {.Required = true})};
}

std::wstring AciRunCommand::ShortDescription() const
{
    return Localization::WSLCCLI_AciRunDesc();
}

std::wstring AciRunCommand::LongDescription() const
{
    return Localization::WSLCCLI_AciRunLongDesc();
}

void AciRunCommand::ExecuteInternal(CLIExecutionContext& Context) const
{
    services::WarningCallback warning(Context.Terminal);
    std::optional<std::wstring> sessionName;
    if (Context.Args.Contains(ArgType::Session))
    {
        sessionName = Context.Args.GetValue<ArgType::Session>();
    }
    Context.ExitCode = wsl::windows::common::wslc::RunAciConfig(
        Context.Args.GetValue<ArgType::AciConfig>(), Context.CreateCancelEvent(), &warning, sessionName ? sessionName->c_str() : nullptr);
}

} // namespace wsl::windows::wslc
