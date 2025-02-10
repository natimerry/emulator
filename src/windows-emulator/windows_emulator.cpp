#include "std_include.hpp"
#include "windows_emulator.hpp"

#include "address_utils.hpp"
#include "context_frame.hpp"

#include <unicorn_x64_emulator.hpp>

#include <utils/io.hpp>
#include <utils/finally.hpp>
#include <utils/compression.hpp>
#include <utils/lazy_object.hpp>

#include "apiset.hpp"
#include "exception_dispatch.hpp"

constexpr auto MAX_INSTRUCTIONS_PER_TIME_SLICE = 100000;

namespace
{
    uint64_t copy_string(x64_emulator& emu, emulator_allocator& allocator, const void* base_ptr, const uint64_t offset,
                         const size_t length)
    {
        if (!length)
        {
            return 0;
        }

        const auto length_to_allocate = length + 2;
        const auto str_obj = allocator.reserve(length_to_allocate);
        emu.write_memory(str_obj, static_cast<const uint8_t*>(base_ptr) + offset, length);

        return str_obj;
    }

    ULONG copy_string_as_relative(x64_emulator& emu, emulator_allocator& allocator, const uint64_t result_base,
                                  const void* base_ptr, const uint64_t offset, const size_t length)
    {
        const auto address = copy_string(emu, allocator, base_ptr, offset, length);
        if (!address)
        {
            return 0;
        }

        assert(address > result_base);
        return static_cast<ULONG>(address - result_base);
    }

    emulator_object<API_SET_NAMESPACE> clone_api_set_map(x64_emulator& emu, emulator_allocator& allocator,
                                                         const API_SET_NAMESPACE& orig_api_set_map)
    {
        const auto api_set_map_obj = allocator.reserve<API_SET_NAMESPACE>();
        const auto ns_entries_obj = allocator.reserve<API_SET_NAMESPACE_ENTRY>(orig_api_set_map.Count);
        const auto hash_entries_obj = allocator.reserve<API_SET_HASH_ENTRY>(orig_api_set_map.Count);

        api_set_map_obj.access([&](API_SET_NAMESPACE& api_set) {
            api_set = orig_api_set_map;
            api_set.EntryOffset = static_cast<ULONG>(ns_entries_obj.value() - api_set_map_obj.value());
            api_set.HashOffset = static_cast<ULONG>(hash_entries_obj.value() - api_set_map_obj.value());
        });

        const auto orig_ns_entries =
            offset_pointer<API_SET_NAMESPACE_ENTRY>(&orig_api_set_map, orig_api_set_map.EntryOffset);
        const auto orig_hash_entries =
            offset_pointer<API_SET_HASH_ENTRY>(&orig_api_set_map, orig_api_set_map.HashOffset);

        for (ULONG i = 0; i < orig_api_set_map.Count; ++i)
        {
            auto ns_entry = orig_ns_entries[i];
            const auto hash_entry = orig_hash_entries[i];

            ns_entry.NameOffset = copy_string_as_relative(emu, allocator, api_set_map_obj.value(), &orig_api_set_map,
                                                          ns_entry.NameOffset, ns_entry.NameLength);

            if (!ns_entry.ValueCount)
            {
                continue;
            }

            const auto values_obj = allocator.reserve<API_SET_VALUE_ENTRY>(ns_entry.ValueCount);
            const auto orig_values = offset_pointer<API_SET_VALUE_ENTRY>(&orig_api_set_map, ns_entry.ValueOffset);

            ns_entry.ValueOffset = static_cast<ULONG>(values_obj.value() - api_set_map_obj.value());

            for (ULONG j = 0; j < ns_entry.ValueCount; ++j)
            {
                auto value = orig_values[j];

                value.ValueOffset = copy_string_as_relative(emu, allocator, api_set_map_obj.value(), &orig_api_set_map,
                                                            value.ValueOffset, value.ValueLength);

                if (value.NameLength)
                {
                    value.NameOffset = copy_string_as_relative(emu, allocator, api_set_map_obj.value(),
                                                               &orig_api_set_map, value.NameOffset, value.NameLength);
                }

                values_obj.write(value, j);
            }

            ns_entries_obj.write(ns_entry, i);
            hash_entries_obj.write(hash_entry, i);
        }

        return api_set_map_obj;
    }

    std::vector<uint8_t> decompress_apiset(const std::vector<uint8_t>& apiset)
    {
        auto buffer = utils::compression::zlib::decompress(apiset);
        if (buffer.empty())
            throw std::runtime_error("Failed to decompress API-SET");
        return buffer;
    }

    std::vector<uint8_t> obtain_api_set(const apiset_location location, const std::filesystem::path& root)
    {
        switch (location)
        {
#ifdef OS_WINDOWS
        case apiset_location::host: {
            const auto apiSetMap =
                reinterpret_cast<const API_SET_NAMESPACE*>(NtCurrentTeb64()->ProcessEnvironmentBlock->ApiSetMap);
            const auto* dataPtr = reinterpret_cast<const uint8_t*>(apiSetMap);
            std::vector<uint8_t> buffer(dataPtr, dataPtr + apiSetMap->Size);
            return buffer;
        }
#else
        case apiset_location::host:
            throw std::runtime_error("The APISET host location is not supported on this platform");
#endif
        case apiset_location::file: {
            const auto apiset = utils::io::read_file(root / "api-set.bin");
            if (apiset.empty())
                throw std::runtime_error("Failed to read file api-set.bin");
            return decompress_apiset(apiset);
        }
        case apiset_location::default_windows_10: {
            const std::vector<uint8_t> apiset{apiset_w10, apiset_w10 + sizeof(apiset_w10)};
            return decompress_apiset(apiset);
        }
        case apiset_location::default_windows_11: {
            const std::vector<uint8_t> apiset{apiset_w11, apiset_w11 + sizeof(apiset_w11)};
            return decompress_apiset(apiset);
        }
        default:
            throw std::runtime_error("Bad API set location");
        }
    }

    emulator_object<API_SET_NAMESPACE> build_api_set_map(x64_emulator& emu, emulator_allocator& allocator,
                                                         const apiset_location location = apiset_location::host,
                                                         const std::filesystem::path& root = {})
    {
        return clone_api_set_map(emu, allocator,
                                 reinterpret_cast<const API_SET_NAMESPACE&>(*obtain_api_set(location, root).data()));
    }

    emulator_allocator create_allocator(memory_manager& memory, const size_t size)
    {
        const auto base = memory.find_free_allocation_base(size);
        memory.allocate_memory(base, size, memory_permission::read_write);

        return emulator_allocator{memory, base, size};
    }

    void setup_gdt(x64_emulator& emu, memory_manager& memory)
    {
        constexpr uint64_t gdtr[4] = {0, GDT_ADDR, GDT_LIMIT, 0};
        emu.write_register(x64_register::gdtr, &gdtr, sizeof(gdtr));
        memory.allocate_memory(GDT_ADDR, GDT_LIMIT, memory_permission::read);

        emu.write_memory<uint64_t>(GDT_ADDR + 6 * (sizeof(uint64_t)), 0xEFFE000000FFFF);
        emu.reg<uint16_t>(x64_register::cs, 0x33);

        emu.write_memory<uint64_t>(GDT_ADDR + 5 * (sizeof(uint64_t)), 0xEFF6000000FFFF);
        emu.reg<uint16_t>(x64_register::ss, 0x2B);
    }

    void setup_context(windows_emulator& win_emu, const emulator_settings& settings, const windows_path& application,
                       const windows_path& working_dir)
    {
        auto& emu = win_emu.emu();
        auto& context = win_emu.process();
        auto& memory = win_emu.memory();

        setup_gdt(emu, memory);

        context.registry =
            registry_manager(win_emu.get_emulation_root().empty() ? settings.registry_directory
                                                                  : win_emu.get_emulation_root() / "registry");

        context.kusd.setup(settings.use_relative_time);

        context.base_allocator = create_allocator(memory, PEB_SEGMENT_SIZE);
        auto& allocator = context.base_allocator;

        context.peb = allocator.reserve<PEB64>();

        /* Values of the following fields must be
         * allocated relative to the process_params themselves
         * and included in the length:
         *
         * CurrentDirectory
         * DllPath
         * ImagePathName
         * CommandLine
         * WindowTitle
         * DesktopInfo
         * ShellInfo
         * RuntimeData
         * RedirectionDllName
         */

        context.process_params = allocator.reserve<RTL_USER_PROCESS_PARAMETERS64>();

        context.process_params.access([&](RTL_USER_PROCESS_PARAMETERS64& proc_params) {
            proc_params.Flags = 0x6001; //| 0x80000000; // Prevent CsrClientConnectToServer

            proc_params.ConsoleHandle = CONSOLE_HANDLE.h;
            proc_params.StandardOutput = STDOUT_HANDLE.h;
            proc_params.StandardInput = STDIN_HANDLE.h;
            proc_params.StandardError = proc_params.StandardOutput;

            proc_params.Environment = reinterpret_cast<std::uint64_t*>(allocator.copy_string(u"=::=::\\"));
            allocator.copy_string(u"EMULATOR=1");
            allocator.copy_string(u"COMPUTERNAME=momo");
            allocator.copy_string(u"SystemRoot=C:\\WINDOWS");
            allocator.copy_string(u"");

            const auto application_str = application.u16string();

            std::u16string command_line = u"\"" + application_str + u"\"";

            for (const auto& arg : settings.arguments)
            {
                command_line.push_back(u' ');
                command_line.append(arg);
            }

            allocator.make_unicode_string(proc_params.CommandLine, command_line);
            allocator.make_unicode_string(proc_params.CurrentDirectory.DosPath, working_dir.u16string() + u"\\", 1024);
            allocator.make_unicode_string(proc_params.ImagePathName, application_str);

            const auto total_length = allocator.get_next_address() - context.process_params.value();

            proc_params.Length =
                static_cast<uint32_t>(std::max(static_cast<uint64_t>(sizeof(proc_params)), total_length));
            proc_params.MaximumLength = proc_params.Length;
        });

        apiset_location apiset_loc = apiset_location::file;

        if (win_emu.get_emulation_root().empty())
        {
#ifdef OS_WINDOWS
            apiset_loc = apiset_location::host;
#else
            apiset_loc = apiset_location::default_windows_11;
#endif
        }

        context.peb.access([&](PEB64& peb) {
            peb.ImageBaseAddress = nullptr;
            peb.ProcessParameters = context.process_params.ptr();
            peb.ApiSetMap = build_api_set_map(emu, allocator, apiset_loc, win_emu.get_emulation_root()).ptr();

            peb.ProcessHeap = nullptr;
            peb.ProcessHeaps = nullptr;
            peb.HeapSegmentReserve = 0x0000000000100000; // TODO: Read from executable
            peb.HeapSegmentCommit = 0x0000000000002000;
            peb.HeapDeCommitTotalFreeThreshold = 0x0000000000010000;
            peb.HeapDeCommitFreeBlockThreshold = 0x0000000000001000;
            peb.NumberOfHeaps = 0x00000000;
            peb.MaximumNumberOfHeaps = 0x00000010;

            peb.OSPlatformId = 2;
            peb.OSMajorVersion = 0x0000000a;
            peb.OSBuildNumber = 0x00006c51;

            // peb.AnsiCodePageData = allocator.reserve<CPTABLEINFO>().value();
            // peb.OemCodePageData = allocator.reserve<CPTABLEINFO>().value();
            peb.UnicodeCaseTableData = allocator.reserve<NLSTABLEINFO>().value();
        });
    }

    void perform_context_switch_work(windows_emulator& win_emu)
    {
        auto& devices = win_emu.process().devices;

        // Crappy mechanism to prevent mutation while iterating.
        const auto was_blocked = devices.block_mutation(true);
        const auto _ = utils::finally([&] { devices.block_mutation(was_blocked); });

        for (auto& dev : devices | std::views::values)
        {
            dev.work(win_emu);
        }
    }

    emulator_thread* get_thread_by_id(process_context& process, const uint32_t id)
    {
        for (auto& t : process.threads | std::views::values)
        {
            if (t.id == id)
            {
                return &t;
            }
        }

        return nullptr;
    }

    bool switch_to_thread(windows_emulator& win_emu, emulator_thread& thread, const bool force = false)
    {
        if (thread.is_terminated())
        {
            return false;
        }

        auto& emu = win_emu.emu();
        auto& context = win_emu.process();

        const auto is_ready = thread.is_thread_ready(context);

        if (!is_ready && !force)
        {
            return false;
        }

        auto* active_thread = context.active_thread;

        if (active_thread == &thread)
        {
            thread.setup_if_necessary(emu, context);
            return true;
        }

        if (active_thread)
        {
            win_emu.log.print(color::dark_gray, "Performing thread switch: %X -> %X\n", active_thread->id, thread.id);
            active_thread->save(emu);
        }

        context.active_thread = &thread;

        thread.restore(emu);
        thread.setup_if_necessary(emu, context);
        return true;
    }

    bool switch_to_thread(windows_emulator& win_emu, const handle thread_handle)
    {
        auto* thread = win_emu.process().threads.get(thread_handle);
        if (!thread)
        {
            throw std::runtime_error("Bad thread handle");
        }

        return switch_to_thread(win_emu, *thread);
    }

    bool switch_to_next_thread(windows_emulator& win_emu)
    {
        perform_context_switch_work(win_emu);

        auto& context = win_emu.process();

        bool next_thread = false;

        for (auto& t : context.threads | std::views::values)
        {
            if (next_thread)
            {
                if (switch_to_thread(win_emu, t))
                {
                    return true;
                }

                continue;
            }

            if (&t == context.active_thread)
            {
                next_thread = true;
            }
        }

        for (auto& t : context.threads | std::views::values)
        {
            if (switch_to_thread(win_emu, t))
            {
                return true;
            }
        }

        return false;
    }
}

std::unique_ptr<x64_emulator> create_default_x64_emulator()
{
    return unicorn::create_x64_emulator();
}

windows_emulator::windows_emulator(const emulator_settings& settings, emulator_callbacks callbacks,
                                   std::unique_ptr<x64_emulator> emu)
    : windows_emulator(settings.emulation_root, std::move(emu))
{
    windows_path working_dir{};

    if (!settings.working_directory.empty())
    {
        working_dir = settings.working_directory;
    }
#ifdef OS_WINDOWS
    else if (settings.application.is_relative())
    {
        working_dir = std::filesystem::current_path();
    }
#endif
    else
    {
        working_dir = settings.application.parent();
    }

    for (const auto& mapping : settings.path_mappings)
    {
        this->file_sys().map(mapping.first, mapping.second);
    }

    for (const auto& mapping : settings.port_mappings)
    {
        this->map_port(mapping.first, mapping.second);
    }

    this->verbose_calls = settings.verbose_calls;
    this->silent_until_main_ = settings.silent_until_main && !settings.disable_logging;
    this->use_relative_time_ = settings.use_relative_time;
    this->log.disable_output(settings.disable_logging || this->silent_until_main_);
    this->callbacks_ = std::move(callbacks);
    this->modules_ = settings.modules;

    this->setup_process(settings, working_dir);
}

windows_emulator::windows_emulator(const std::filesystem::path& emulation_root, std::unique_ptr<x64_emulator> emu)
    : emulation_root_{emulation_root.empty() ? emulation_root : absolute(emulation_root)},
      file_sys_(emulation_root_.empty() ? emulation_root_ : emulation_root_ / "filesys"),
      emu_(std::move(emu)),
      memory_manager_(*this->emu_),
      process_(*emu_, memory_manager_, file_sys_)
{
#ifndef OS_WINDOWS
    if (this->get_emulation_root().empty())
    {
        throw std::runtime_error("Emulation root directory can not be empty!");
    }
#endif

    this->setup_hooks();
}

windows_emulator::~windows_emulator() = default;

void windows_emulator::setup_process(const emulator_settings& settings, const windows_path& working_directory)
{
    auto& emu = this->emu();

    auto& context = this->process();
    context.mod_manager = module_manager(this->memory(), this->file_sys()); // TODO: Cleanup module manager

    const auto application = settings.application.is_absolute() //
                                 ? settings.application
                                 : (working_directory / settings.application);

    setup_context(*this, settings, application, working_directory);

    context.executable = context.mod_manager.map_module(application, this->log, true);

    context.peb.access([&](PEB64& peb) {
        peb.ImageBaseAddress = reinterpret_cast<std::uint64_t*>(context.executable->image_base); //
    });

    context.ntdll = context.mod_manager.map_module(R"(C:\Windows\System32\ntdll.dll)", this->log, true);
    context.win32u = context.mod_manager.map_module(R"(C:\Windows\System32\win32u.dll)", this->log, true);

    const auto ntdll_data = emu.read_memory(context.ntdll->image_base, context.ntdll->size_of_image);
    const auto win32u_data = emu.read_memory(context.win32u->image_base, context.win32u->size_of_image);

    this->dispatcher_.setup(context.ntdll->exports, ntdll_data, context.win32u->exports, win32u_data);

    context.ldr_initialize_thunk = context.ntdll->find_export("LdrInitializeThunk");
    context.rtl_user_thread_start = context.ntdll->find_export("RtlUserThreadStart");
    context.ki_user_exception_dispatcher = context.ntdll->find_export("KiUserExceptionDispatcher");

    context.default_register_set = emu.save_registers();

    const auto main_thread_id = context.create_thread(this->memory(), context.executable->entry_point, 0, 0);
    switch_to_thread(*this, main_thread_id);
}

void windows_emulator::yield_thread()
{
    this->switch_thread_ = true;
    this->emu().stop();
}

void windows_emulator::perform_thread_switch()
{
    this->switch_thread_ = false;
    while (!switch_to_next_thread(*this))
    {
        // TODO: Optimize that
        std::this_thread::sleep_for(1ms);
    }
}

bool windows_emulator::activate_thread(const uint32_t id)
{
    const auto thread = get_thread_by_id(this->process(), id);
    if (!thread)
    {
        return false;
    }

    return switch_to_thread(*this, *thread, true);
}

void windows_emulator::on_instruction_execution(const uint64_t address)
{
    auto& process = this->process();
    auto& thread = this->current_thread();

    ++process.executed_instructions;
    const auto thread_insts = ++thread.executed_instructions;
    if (thread_insts % MAX_INSTRUCTIONS_PER_TIME_SLICE == 0)
    {
        this->yield_thread();
    }

    process.previous_ip = process.current_ip;
    process.current_ip = this->emu().read_instruction_pointer();

    const auto binary = utils::make_lazy([&] {
        return this->process().mod_manager.find_by_address(address); //
    });

    const auto previous_binary = utils::make_lazy([&] {
        return this->process().mod_manager.find_by_address(process.previous_ip); //
    });

    const auto is_in_interesting_module = [&] {
        if (this->modules_.empty())
        {
            return false;
        }

        return (binary && this->modules_.contains(binary->name)) ||
               (previous_binary && this->modules_.contains(previous_binary->name));
    };

    const auto is_main_exe = process.executable->is_within(address);
    const auto is_interesting_call = process.executable->is_within(process.previous_ip) //
                                     || is_main_exe                                     //
                                     || is_in_interesting_module();

    if (this->silent_until_main_ && is_main_exe)
    {
        this->silent_until_main_ = false;
        this->log.disable_output(false);
    }

    if (!this->verbose && !this->verbose_calls && !is_interesting_call)
    {
        return;
    }

    if (binary)
    {
        const auto export_entry = binary->address_names.find(address);
        if (export_entry != binary->address_names.end())
        {
            const auto rsp = this->emu().read_stack_pointer();

            uint64_t return_address{};
            this->emu().try_read_memory(rsp, &return_address, sizeof(return_address));

            const auto* mod_name = this->process().mod_manager.find_name(return_address);

            log.print(is_interesting_call ? color::yellow : color::dark_gray,
                      "Executing function: %s - %s (0x%" PRIx64 ") via (0x%" PRIx64 ") %s\n", binary->name.c_str(),
                      export_entry->second.c_str(), address, return_address, mod_name);
        }
        else if (address == binary->entry_point)
        {
            log.print(is_interesting_call ? color::yellow : color::gray, "Executing entry point: %s (0x%" PRIx64 ")\n",
                      binary->name.c_str(), address);
        }
    }

    if (!this->verbose)
    {
        return;
    }

    auto& emu = this->emu();

    log.print(color::gray,
              "Inst: %16" PRIx64 " - RAX: %16" PRIx64 " - RBX: %16" PRIx64 " - RCX: %16" PRIx64 " - RDX: %16" PRIx64
              " - R8: %16" PRIx64 " - R9: %16" PRIx64 " - RDI: %16" PRIx64 " - RSI: %16" PRIx64 " - %s\n",
              address, emu.reg(x64_register::rax), emu.reg(x64_register::rbx), emu.reg(x64_register::rcx),
              emu.reg(x64_register::rdx), emu.reg(x64_register::r8), emu.reg(x64_register::r9),
              emu.reg(x64_register::rdi), emu.reg(x64_register::rsi), binary ? binary->name.c_str() : "<N/A>");
}

void windows_emulator::setup_hooks()
{
    this->emu().hook_instruction(x64_hookable_instructions::syscall, [&] {
        for (const auto& hook : this->syscall_hooks_)
        {
            if (hook() == instruction_hook_continuation::skip_instruction)
            {
                return instruction_hook_continuation::skip_instruction;
            }
        }

        this->dispatcher_.dispatch(*this);
        return instruction_hook_continuation::skip_instruction;
    });

    this->emu().hook_instruction(x64_hookable_instructions::rdtsc, [&] {
        const auto instructions = this->process().executed_instructions;
        this->emu().reg(x64_register::rax, instructions & 0xFFFFFFFF);
        this->emu().reg(x64_register::rdx, (instructions >> 32) & 0xFFFFFFFF);
        return instruction_hook_continuation::skip_instruction;
    });

    this->emu().hook_instruction(x64_hookable_instructions::invalid, [&] {
        const auto ip = this->emu().read_instruction_pointer();

        this->log.print(color::gray, "Invalid instruction at: 0x%" PRIx64 "\n", ip);

        return instruction_hook_continuation::skip_instruction;
    });

    this->emu().hook_interrupt([&](const int interrupt) {
        const auto rip = this->emu().read_instruction_pointer();

        switch (interrupt)
        {
        case 0:
            dispatch_integer_division_by_zero(this->emu(), this->process());
            return;
        case 1:
            this->log.print(color::pink, "Singlestep: 0x%" PRIx64 "\n", rip);
            dispatch_single_step(this->emu(), this->process());
            return;
        case 6:
            dispatch_illegal_instruction_violation(this->emu(), this->process());
            return;
        default:
            break;
        }

        this->log.print(color::gray, "Interrupt: %i 0x%" PRIx64 "\n", interrupt, rip);

        if (this->fuzzing || true) // TODO: Fix
        {
            this->process().exception_rip = rip;
            this->emu().stop();
        }
    });

    this->emu().hook_memory_violation([&](const uint64_t address, const size_t size, const memory_operation operation,
                                          const memory_violation_type type) {
        const auto permission = get_permission_string(operation);
        const auto ip = this->emu().read_instruction_pointer();
        const char* name = this->process().mod_manager.find_name(ip);

        if (type == memory_violation_type::protection)
        {
            this->log.print(color::gray, "Protection violation: 0x%" PRIx64 " (%zX) - %s at 0x%" PRIx64 " (%s)\n",
                            address, size, permission.c_str(), ip, name);
        }
        else if (type == memory_violation_type::unmapped)
        {
            this->log.print(color::gray, "Mapping violation: 0x%" PRIx64 " (%zX) - %s at 0x%" PRIx64 " (%s)\n", address,
                            size, permission.c_str(), ip, name);
        }

        if (this->fuzzing)
        {
            this->process().exception_rip = ip;
            this->emu().stop();
            return memory_violation_continuation::stop;
        }

        dispatch_access_violation(this->emu(), this->process(), address, operation);
        return memory_violation_continuation::resume;
    });

    this->emu().hook_memory_execution(
        0, std::numeric_limits<size_t>::max(),
        [&](const uint64_t address, const size_t, const uint64_t) { this->on_instruction_execution(address); });
}

void windows_emulator::start(std::chrono::nanoseconds timeout, size_t count)
{
    const auto use_count = count > 0;
    const auto use_timeout = timeout != std::chrono::nanoseconds{};

    const auto start_time = std::chrono::high_resolution_clock::now();
    const auto start_instructions = this->process().executed_instructions;

    const auto target_time = start_time + timeout;
    const auto target_instructions = start_instructions + count;

    while (true)
    {
        if (this->switch_thread_ || !this->current_thread().is_thread_ready(this->process()))
        {
            this->perform_thread_switch();
        }

        this->emu().start_from_ip(timeout, count);

        if (!this->switch_thread_ && !this->emu().has_violation())
        {
            break;
        }

        if (use_timeout)
        {
            const auto now = std::chrono::high_resolution_clock::now();

            if (now >= target_time)
            {
                break;
            }

            timeout = target_time - now;
        }

        if (use_count)
        {
            const auto current_instructions = this->process().executed_instructions;

            if (current_instructions >= target_instructions)
            {
                break;
            }

            count = target_instructions - current_instructions;
        }
    }
}

void windows_emulator::serialize(utils::buffer_serializer& buffer) const
{
    buffer.write(this->switch_thread_);
    buffer.write(this->use_relative_time_);
    this->emu().serialize_state(buffer, false);
    this->memory().serialize_memory_state(buffer, false);
    this->process_.serialize(buffer);
    this->dispatcher_.serialize(buffer);
}

void windows_emulator::deserialize(utils::buffer_deserializer& buffer)
{
    buffer.register_factory<memory_manager_wrapper>([this] {
        return memory_manager_wrapper{this->memory()}; //
    });

    buffer.register_factory<x64_emulator_wrapper>([this] {
        return x64_emulator_wrapper{this->emu()}; //
    });

    buffer.register_factory<windows_emulator_wrapper>([this] {
        return windows_emulator_wrapper{*this}; //
    });

    buffer.read(this->switch_thread_);
    buffer.read(this->use_relative_time_);

    this->memory().unmap_all_memory();

    this->emu().deserialize_state(buffer, false);
    this->memory().deserialize_memory_state(buffer, false);
    this->process_.deserialize(buffer);
    this->dispatcher_.deserialize(buffer);
}

void windows_emulator::save_snapshot()
{
    utils::buffer_serializer serializer{};
    this->emu().serialize_state(serializer, true);
    this->memory().serialize_memory_state(serializer, true);
    this->process_.serialize(serializer);

    this->process_snapshot_ = serializer.move_buffer();

    // TODO: Make process copyable
    // this->process_snapshot_ = this->process();
}

void windows_emulator::restore_snapshot()
{
    if (this->process_snapshot_.empty())
    {
        assert(false);
        return;
    }

    utils::buffer_deserializer deserializer{this->process_snapshot_};
    this->emu().deserialize_state(deserializer, true);
    this->memory().deserialize_memory_state(deserializer, true);
    this->process_.deserialize(deserializer);
    // this->process_ = *this->process_snapshot_;
}
