// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#include "Command.h"

namespace wsl::windows::wslc {

struct AciCommand final : public Command
{
    constexpr static std::wstring_view CommandName = L"aci";
    explicit AciCommand(const std::wstring& Parent) : Command(CommandName, Parent)
    {
    }

    std::wstring ShortDescription() const override;
    std::wstring LongDescription() const override;

protected:
    std::vector<std::unique_ptr<Command>> CreateCommands() const override;
    void ExecuteInternal(CLIExecutionContext& Context) const override;
};

struct AciRunCommand final : public Command
{
    constexpr static std::wstring_view CommandName = L"run";
    explicit AciRunCommand(const std::wstring& Parent) : Command(CommandName, Parent)
    {
    }

    std::vector<Argument> GetArguments() const override;
    std::wstring ShortDescription() const override;
    std::wstring LongDescription() const override;

protected:
    void ExecuteInternal(CLIExecutionContext& Context) const override;
};

} // namespace wsl::windows::wslc
