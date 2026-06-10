#pragma once

#include <cstdint>
#include <memory>
#include <arch_emulator.hpp>

namespace sogen
{

    enum class backend_type : uint8_t
    {
        automatic,
        unicorn,
        icicle,
        whp,
    };

    std::unique_ptr<x86_64_emulator> create_x86_64_emulator(backend_type backend = backend_type::automatic);
    std::unique_ptr<x86_64_emulator> create_x86_64_emulator_from_environment();
} // namespace sogen
