#include "module.pe.hpp"

#include <cassert>
#include <zasm/serialization/serializer.hpp>

namespace zasm::modules
{
    static LIEF::PE::PE_TYPE getPEType(const Program& program)
    {
        auto peType = LIEF::PE::PE_TYPE::PE32;
        if (program.getMode() == zasm::MachineMode::AMD64)
            peType = LIEF::PE::PE_TYPE::PE32_PLUS;
        return peType;
    }

    ModulePE::ModulePE(const Program& program, const char* name)
        : _program(program)
        , _binary(name, getPEType(program))
    {
    }

    static Error serializeProgramToBinary(zasm::Serializer& serializer, const Program& program, LIEF::PE::Binary& binary)
    {
        const uint64_t imageBase = 0x00400000;
        const uint64_t sectRVA = 0x1000;

        if (auto err = serializer.serialize(program, imageBase + sectRVA); err != zasm::Error::None)
        {
            return err;
        }

        const uint8_t* codeBuffer = serializer.getCode();

        binary.optional_header().imagebase(imageBase);

        // Create the sections.
        for (size_t i = 0; i < serializer.getSectionCount(); ++i)
        {
            const auto* sectInfo = serializer.getSectionInfo(i);
            assert(sectInfo != nullptr);

            std::vector<uint8_t> sectBuf;
            sectBuf.resize(sectInfo->physicalSize);

            if (sectInfo->physicalSize > 0)
            {
                std::memcpy(sectBuf.data(), codeBuffer + sectInfo->offset, sectInfo->physicalSize);
            }

            LIEF::PE::Section newSect(sectInfo->name);
            newSect.content(sectBuf);
            newSect.virtual_address(sectInfo->address - imageBase); // RVA
            newSect.virtual_size(sectInfo->virtualSize);
            if ((sectInfo->attribs & zasm::Section::Attribs::Code) != zasm::Section::Attribs::None)
                newSect.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);
            if ((sectInfo->attribs & zasm::Section::Attribs::Exec) != zasm::Section::Attribs::None)
                newSect.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
            if ((sectInfo->attribs & zasm::Section::Attribs::Read) != zasm::Section::Attribs::None)
                newSect.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
            if ((sectInfo->attribs & zasm::Section::Attribs::Write) != zasm::Section::Attribs::None)
                newSect.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

            binary.add_section(newSect);
        }

        return Error::None;
    }

    static Error serializeImports(zasm::Serializer& serializer, const Program& program, LIEF::PE::Binary& binary)
    {
        std::vector<std::pair<const char*, std::vector<const char*>>> imports;

        const auto addImport = [&](const char* mod, const char* func) {
            auto itGroup = std::find_if(
                imports.begin(), imports.end(), [&](auto&& entry) { return strcmp(entry.first, mod) == 0; });
            if (itGroup == imports.end())
            {
                imports.emplace_back(mod, std::vector<const char*>{ func });
            }
            else
            {
                auto& group = itGroup->second;
                auto itEntry = std::find_if(group.begin(), group.end(), [&](const char* fn) { return strcmp(fn, func) == 0; });
                if (itEntry == group.end())
                {
                    group.push_back(func);
                }
            }
        };

        // Build the import table by its used references, unused imports will not be added.
        for (size_t i = 0; i < serializer.getExternalRelocationCount(); ++i)
        {
            const zasm::RelocationInfo* relocData = serializer.getExternalRelocation(i);
            if (relocData->label != zasm::Label::Id::Invalid)
            {
                auto labelData = program.getLabelData(zasm::Label{ relocData->label });
                if ((labelData->flags & zasm::LabelFlags::Import) == zasm::LabelFlags::None)
                    continue;

                addImport(labelData->moduleName, labelData->name);
            }
        }

        // Generate the imports in the binary.
        std::sort(imports.begin(), imports.end(), [](auto&& lhs, auto&& rhs) { return strcmp(lhs.first, rhs.first) < 0; });
        for (auto& [mod, entries] : imports)
        {
            auto& lib = binary.add_library(mod);

            std::sort(entries.begin(), entries.end(), [](auto&& lhs, auto&& rhs) { return strcmp(lhs, rhs) < 0; });
            for (const char* func : entries)
            {
                lib.add_entry(func);
            }
        }

        // Fix the references.
        for (size_t i = 0; i < serializer.getExternalRelocationCount(); ++i)
        {
            const zasm::RelocationInfo* relocData = serializer.getExternalRelocation(i);
            if (relocData->label != zasm::Label::Id::Invalid)
            {
                auto labelData = program.getLabelData(zasm::Label{ relocData->label });
                if ((labelData->flags & zasm::LabelFlags::Import) == zasm::LabelFlags::None)
                    continue;

                const uint32_t funcRVA = binary.predict_function_rva(labelData->moduleName, labelData->name);
                const uint64_t funcVA = binary.imagebase() + funcRVA;

                if (relocData->kind == RelocationType::Rel32)
                {
                    uint64_t rel = funcVA - (relocData->address + 4);
                    uint32_t rel32 = static_cast<uint32_t>(rel);

                    binary.patch_address(relocData->address, rel, 4, LIEF::Binary::VA_TYPES::VA);
                }
            }
        }

        return Error::None;
    }

    static Error serializeExports(zasm::Serializer& serializer, const Program& program, LIEF::PE::Binary& binary)
    {
        // Currently unsupported.
        return Error::None;
    }

    static Error serializeRelocations(zasm::Serializer& serializer, const Program& program, LIEF::PE::Binary& binary)
    {
        // Currently unsupported.
        return Error::None;
    }

    static Error serializeEntryPoints(zasm::Serializer& serializer, const Program& program, LIEF::PE::Binary& binary)
    {
        auto entryLabel = program.getEntryPoint();
        if (entryLabel.isValid())
        {
            const auto entryVA = serializer.getLabelAddress(entryLabel.getId());
            if (entryVA != 0)
            {
                const auto entryRVA = entryVA - binary.imagebase();
                binary.optional_header().addressof_entrypoint(static_cast<uint32_t>(entryRVA));
            }
        }

        return Error::None;
    }

    Error ModulePE::serialize()
    {
        zasm::Serializer serializer;

        // Program
        if (auto err = serializeProgramToBinary(serializer, _program, _binary); err != Error::None)
        {
            return err;
        }

        // Imports
        if (auto err = serializeImports(serializer, _program, _binary); err != Error::None)
        {
            return err;
        }

        // Exports
        if (auto err = serializeExports(serializer, _program, _binary); err != Error::None)
        {
            return err;
        }

        // Relocations
        if (auto err = serializeRelocations(serializer, _program, _binary); err != Error::None)
        {
            return err;
        }

        // Relocations
        if (auto err = serializeEntryPoints(serializer, _program, _binary); err != Error::None)
        {
            return err;
        }

        return Error::None;
    }

    Error ModulePE::save(const std::filesystem::path& filePath)
    {
        LIEF::PE::Builder builder(_binary);

        builder.build_imports();
        builder.build();
        builder.write(filePath.string());

        return Error::None;
    }

} // namespace zasm::modules