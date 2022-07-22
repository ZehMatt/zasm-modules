#pragma once

#include <filesystem>
#include <memory>
#include <zasm/program/program.hpp>

namespace zasm::modules
{
    enum class ModuleType
    {
        PE,
    };

    class Module
    {
    public:
        virtual ~Module() = default;

        virtual ModuleType getModuleType() const = 0;

        virtual Error serialize() = 0;

        virtual Error save(const std::filesystem::path& filePath) = 0;
    };

    std::unique_ptr<Module> createModule(const ModuleType type, const Program& program, const char* name);

} // namespace zasm::frontend