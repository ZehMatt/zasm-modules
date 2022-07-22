#pragma once

#include <LIEF/PE.hpp>
#include <string>
#include <zasm/modules/module.hpp>

namespace zasm::modules
{
    class ModulePE final : public Module
    {
        const Program& _program;
        LIEF::PE::Binary _binary;

    public:
        ModulePE(const Program& program, const char* name);

        ModuleType getModuleType() const override
        {
            return ModuleType::PE;
        }

        Error serialize() override;

        Error save(const std::filesystem::path& filePath) override;
    };

} // namespace zasm::modules