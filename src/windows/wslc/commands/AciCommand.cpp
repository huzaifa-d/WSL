// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "AciCommand.h"
#include "CLIExecutionContext.h"

using namespace wsl::windows::wslc::execution;
using namespace wsl::shared;

namespace wsl::windows::wslc {

std::vector<std::unique_ptr<Command>> AciCommand::CreateCommands() const
{
    std::vector<std::unique_ptr<Command>> commands;
    commands.push_back(std::make_unique<AciRunCommand>(FullName()));
    return commands;
}

std::wstring AciCommand::ShortDescription() const
{
    return Localization::WSLCCLI_AciCommandDesc();
}

std::wstring AciCommand::LongDescription() const
{
    return Localization::WSLCCLI_AciCommandLongDesc();
}

void AciCommand::ExecuteInternal(CLIExecutionContext& Context) const
{
    OutputHelp(Context.Terminal);
}

} // namespace wsl::windows::wslc
