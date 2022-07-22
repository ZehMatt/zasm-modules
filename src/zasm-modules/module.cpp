#include "module.pe.hpp"

#include <zasm/modules/module.hpp>

namespace zasm::modules
{

    std::unique_ptr<Module> createModule(const ModuleType type, const Program& program, const char* name)
    {
        if (type == ModuleType::PE)
            return std::make_unique<ModulePE>(program, name);

        return nullptr;
    }

} // namespace zasm::frontend