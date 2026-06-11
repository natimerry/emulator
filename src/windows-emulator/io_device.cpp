#include "std_include.hpp"
#include "io_device.hpp"
#include "windows_emulator.hpp"
#include "devices/afd_endpoint.hpp"
#include "devices/mount_point_manager.hpp"
#include "devices/security_support_provider.hpp"
#include "devices/named_pipe.hpp"
#include "devices/network_store_interface.hpp"
#include "devices/gpu_bridge.hpp"
#include <utils/finally.hpp>
#ifdef OS_WINDOWS
#include <iphlpapi.h>
#endif
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iostream>

namespace sogen
{

    namespace
    {
        struct dummy_device : stateless_device
        {
            NTSTATUS io_control(windows_emulator&, const io_device_context&) override
            {
                return STATUS_SUCCESS;
            }
        };

        constexpr ULONG k_ioctl_tcp_query_information_ex = 0x120003;

        constexpr ULONG k_info_class_generic = 0x100;
        constexpr ULONG k_info_class_protocol = 0x200;
        constexpr ULONG k_info_type_provider = 0x100;

        constexpr ULONG k_entity_list_id = 0;
        constexpr ULONG k_entity_type_id = 1;
        constexpr ULONG k_if_mib_stats_id = 1;
        constexpr ULONG k_ip_mib_stats_id = 1;
        constexpr ULONG k_ip_mib_addrtable_entry_id = 0x102;

        constexpr ULONG k_generic_entity = 0;
        constexpr ULONG k_if_entity = 0x200;
        constexpr ULONG k_at_entity = 0x280;
        constexpr ULONG k_cl_nl_entity = 0x301;
        constexpr ULONG k_co_tl_entity = 0x400;
        constexpr ULONG k_cl_tl_entity = 0x401;

        constexpr ULONG k_if_mib = 0x202;
        constexpr ULONG k_at_null = 0x282;
        constexpr ULONG k_cl_nl_ip = 0x303;
        constexpr ULONG k_co_tl_tcp = 0x404;
        constexpr ULONG k_cl_tl_udp = 0x403;

        struct tdi_entity_id
        {
            ULONG entity{};
            ULONG instance{};
        };

        struct tdi_object_id
        {
            tdi_entity_id entity{};
            ULONG info_class{};
            ULONG info_type{};
            ULONG info_id{};
        };

        struct tcp_request_query_information_ex
        {
            tdi_object_id id{};
            std::array<ULONG, 4> context{};
        };

        struct ip_snmp_info
        {
            ULONG forwarding{};
            ULONG default_ttl{};
            ULONG in_receives{};
            ULONG in_header_errors{};
            ULONG in_address_errors{};
            ULONG forwarded_datagrams{};
            ULONG in_unknown_protocols{};
            ULONG in_discards{};
            ULONG in_delivers{};
            ULONG out_requests{};
            ULONG routing_discards{};
            ULONG out_discards{};
            ULONG out_no_routes{};
            ULONG reassembly_timeout{};
            ULONG reassembly_required{};
            ULONG reassembly_ok{};
            ULONG reassembly_failed{};
            ULONG fragment_ok{};
            ULONG fragment_failed{};
            ULONG fragment_created{};
            ULONG interface_count{};
            ULONG address_count{};
            ULONG route_count{};
        };

        struct ip_address_entry
        {
            ULONG address{};
            ULONG interface_index{};
            ULONG mask{};
            ULONG broadcast_address{};
            ULONG reassembly_size{};
            USHORT context{};
            USHORT pad{};
        };

        struct interface_entry_prefix
        {
            ULONG index{};
            ULONG type{};
            ULONG mtu{};
            ULONG speed{};
            ULONG physical_address_length{};
            std::array<UCHAR, 8> physical_address{};
            ULONG admin_status{};
            ULONG operational_status{};
            ULONG last_change{};
            ULONG in_octets{};
            ULONG in_unicast_packets{};
            ULONG in_non_unicast_packets{};
            ULONG in_discards{};
            ULONG in_errors{};
            ULONG in_unknown_protocols{};
            ULONG out_octets{};
            ULONG out_unicast_packets{};
            ULONG out_non_unicast_packets{};
            ULONG out_discards{};
            ULONG out_errors{};
            ULONG out_queue_length{};
            ULONG description_length{};
        };

        struct network_identity
        {
            ULONG interface_index{1};
            ULONG interface_type{6};
            ULONG mtu{1500};
            ULONG speed{1000000000};
            ULONG address{0};
            ULONG mask{0};
            ULONG physical_address_length{6};
            std::array<UCHAR, 8> physical_address{0x02, 0x15, 0x5D, 0x12, 0x34, 0x56, 0, 0};
            ULONG admin_status{1};
            ULONG operational_status{1};
            ULONG last_change{};
            ULONG in_octets{};
            ULONG in_unicast_packets{};
            ULONG in_non_unicast_packets{};
            ULONG in_discards{};
            ULONG in_errors{};
            ULONG in_unknown_protocols{};
            ULONG out_octets{};
            ULONG out_unicast_packets{};
            ULONG out_non_unicast_packets{};
            ULONG out_discards{};
            ULONG out_errors{};
            ULONG out_queue_length{};
            std::array<UCHAR, 256> description{'V', 'M', 'D', 'e', 'd', ' ', 'E', 't', 'h', 'e', 'r', 'n', 'e', 't'};
            ULONG description_length{0};
        };

        static_assert(sizeof(tdi_object_id) == 20);
        static_assert(sizeof(tcp_request_query_information_ex) == 36);
        static_assert(sizeof(ip_snmp_info) == 92);
        static_assert(sizeof(ip_address_entry) == 24);
        static_assert(sizeof(interface_entry_prefix) == 92);

        ULONG ipv4_address(const UCHAR a, const UCHAR b, const UCHAR c, const UCHAR d)
        {
            return static_cast<ULONG>(a) | (static_cast<ULONG>(b) << 8) | (static_cast<ULONG>(c) << 16) |
                   (static_cast<ULONG>(d) << 24);
        }

        network_identity default_network_identity()
        {
            network_identity identity{};
            identity.address = ipv4_address(192, 168, 56, 2);
            identity.mask = ipv4_address(255, 255, 255, 0);
            return identity;
        }

        std::optional<ULONG> parse_ipv4_address(const std::string_view text)
        {
            std::array<UCHAR, 4> parts{};
            size_t part_index = 0;
            size_t cursor = 0;

            while (part_index < parts.size())
            {
                if (cursor >= text.size())
                {
                    return std::nullopt;
                }

                unsigned value = 0;
                size_t digits = 0;
                while (cursor < text.size() && text[cursor] >= '0' && text[cursor] <= '9')
                {
                    value = (value * 10) + static_cast<unsigned>(text[cursor] - '0');
                    if (value > 255)
                    {
                        return std::nullopt;
                    }
                    ++cursor;
                    ++digits;
                }

                if (!digits)
                {
                    return std::nullopt;
                }

                parts[part_index++] = static_cast<UCHAR>(value);
                if (part_index == parts.size())
                {
                    break;
                }
                if (cursor >= text.size() || text[cursor++] != '.')
                {
                    return std::nullopt;
                }
            }

            if (cursor != text.size())
            {
                return std::nullopt;
            }

            return ipv4_address(parts[0], parts[1], parts[2], parts[3]);
        }

        bool is_zero_mac(const BYTE* address, const ULONG length)
        {
            for (ULONG i = 0; i < length; ++i)
            {
                if (address[i] != 0)
                {
                    return false;
                }
            }

            return true;
        }

        bool contains_case_insensitive(std::string text, const std::string_view needle)
        {
            std::ranges::transform(text, text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return text.find(needle) != std::string::npos;
        }

        bool is_virtual_adapter_description(const std::string& description)
        {
            return contains_case_insensitive(description, "virtual") || contains_case_insensitive(description, "hyper-v") ||
                   contains_case_insensitive(description, "wsl") || contains_case_insensitive(description, "loopback") ||
                   contains_case_insensitive(description, "bluetooth") || contains_case_insensitive(description, "tunnel");
        }

        void set_description(network_identity& identity, const std::string_view description)
        {
            identity.description = {};
            const auto size = std::min(description.size(), identity.description.size());
            for (size_t i = 0; i < size; ++i)
            {
                identity.description[i] = static_cast<UCHAR>(description[i]);
            }
            identity.description_length = static_cast<ULONG>(size);
        }

#ifdef OS_WINDOWS
        std::optional<network_identity> read_host_network_identity()
        {
            ULONG buffer_size = 0;
            auto status = GetAdaptersInfo(nullptr, &buffer_size);
            if (status != ERROR_BUFFER_OVERFLOW || buffer_size == 0)
            {
                return std::nullopt;
            }

            std::vector<std::byte> buffer(buffer_size);
            auto* adapters = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
            status = GetAdaptersInfo(adapters, &buffer_size);
            if (status != NO_ERROR)
            {
                return std::nullopt;
            }

            for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next)
            {
                const auto description = std::string{adapter->Description};
                const auto address = parse_ipv4_address(adapter->IpAddressList.IpAddress.String);
                const auto mask = parse_ipv4_address(adapter->IpAddressList.IpMask.String);
                if (!address || *address == 0 || !mask || adapter->AddressLength < 6 ||
                    adapter->AddressLength > MAX_ADAPTER_ADDRESS_LENGTH || is_zero_mac(adapter->Address, adapter->AddressLength) ||
                    is_virtual_adapter_description(description))
                {
                    continue;
                }

                network_identity identity{};
                identity.interface_index = adapter->Index ? adapter->Index : 1;
                identity.interface_type = adapter->Type ? adapter->Type : 6;
                identity.address = *address;
                identity.mask = *mask;
                identity.physical_address_length =
                    std::min<ULONG>(adapter->AddressLength, static_cast<ULONG>(identity.physical_address.size()));
                std::ranges::copy_n(adapter->Address, identity.physical_address_length, identity.physical_address.begin());
                set_description(identity, description);

                MIB_IFROW row{};
                row.dwIndex = identity.interface_index;
                if (GetIfEntry(&row) == NO_ERROR)
                {
                    identity.interface_type = row.dwType ? row.dwType : identity.interface_type;
                    identity.mtu = row.dwMtu ? row.dwMtu : identity.mtu;
                    identity.speed = row.dwSpeed ? row.dwSpeed : identity.speed;
                    identity.physical_address_length =
                        std::min<ULONG>(row.dwPhysAddrLen, static_cast<ULONG>(identity.physical_address.size()));
                    std::ranges::copy_n(row.bPhysAddr, identity.physical_address_length, identity.physical_address.begin());
                    identity.admin_status = row.dwAdminStatus;
                    identity.operational_status = row.dwOperStatus;
                    identity.last_change = row.dwLastChange;
                    identity.in_octets = row.dwInOctets;
                    identity.in_unicast_packets = row.dwInUcastPkts;
                    identity.in_non_unicast_packets = row.dwInNUcastPkts;
                    identity.in_discards = row.dwInDiscards;
                    identity.in_errors = row.dwInErrors;
                    identity.in_unknown_protocols = row.dwInUnknownProtos;
                    identity.out_octets = row.dwOutOctets;
                    identity.out_unicast_packets = row.dwOutUcastPkts;
                    identity.out_non_unicast_packets = row.dwOutNUcastPkts;
                    identity.out_discards = row.dwOutDiscards;
                    identity.out_errors = row.dwOutErrors;
                    identity.out_queue_length = row.dwOutQLen;
                    identity.description = {};
                    identity.description_length =
                        std::min<ULONG>(row.dwDescrLen, static_cast<ULONG>(identity.description.size()));
                    std::ranges::copy_n(row.bDescr, identity.description_length, identity.description.begin());
                }
                return identity;
            }

            return std::nullopt;
        }
#endif

        const network_identity& host_network_identity()
        {
#ifdef OS_WINDOWS
            static const auto identity = read_host_network_identity().value_or(default_network_identity());
#else
            static const auto identity = default_network_identity();
#endif
            return identity;
        }

        void write_io_information(const io_device_context& c, const uint64_t information)
        {
            if (!c.io_status_block)
            {
                return;
            }

            IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
            block.Information = information;
            c.io_status_block.write(block);
        }

        NTSTATUS write_output_bytes(windows_emulator& win_emu, const io_device_context& c, const std::span<const std::byte> bytes)
        {
            const auto bytes_to_write = std::min<size_t>(bytes.size(), c.output_buffer_length);
            if (c.output_buffer && bytes_to_write)
            {
                win_emu.emu().write_memory(c.output_buffer, bytes.data(), bytes_to_write);
            }

            write_io_information(c, bytes_to_write);
            return bytes_to_write < bytes.size() ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        }

        template <typename T>
        NTSTATUS write_output(windows_emulator& win_emu, const io_device_context& c, const T& value)
        {
            const auto bytes = std::as_bytes(std::span<const T>{&value, 1});
            return write_output_bytes(win_emu, c, bytes);
        }

        template <typename T>
        NTSTATUS write_output_array(windows_emulator& win_emu, const io_device_context& c, const std::span<const T> values)
        {
            const auto bytes = std::as_bytes(values);
            return write_output_bytes(win_emu, c, bytes);
        }

        NTSTATUS write_interface_entry(windows_emulator& win_emu, const io_device_context& c, const network_identity& identity)
        {
            const auto max_description_length =
                c.output_buffer_length > sizeof(interface_entry_prefix) ? c.output_buffer_length - sizeof(interface_entry_prefix) : 0;
            const auto description_length =
                std::min<size_t>({identity.description_length, identity.description.size(), max_description_length});
            const interface_entry_prefix entry{
                .index = identity.interface_index,
                .type = identity.interface_type,
                .mtu = identity.mtu,
                .speed = identity.speed,
                .physical_address_length = identity.physical_address_length,
                .physical_address = identity.physical_address,
                .admin_status = identity.admin_status,
                .operational_status = identity.operational_status,
                .last_change = identity.last_change,
                .in_octets = identity.in_octets,
                .in_unicast_packets = identity.in_unicast_packets,
                .in_non_unicast_packets = identity.in_non_unicast_packets,
                .in_discards = identity.in_discards,
                .in_errors = identity.in_errors,
                .in_unknown_protocols = identity.in_unknown_protocols,
                .out_octets = identity.out_octets,
                .out_unicast_packets = identity.out_unicast_packets,
                .out_non_unicast_packets = identity.out_non_unicast_packets,
                .out_discards = identity.out_discards,
                .out_errors = identity.out_errors,
                .out_queue_length = identity.out_queue_length,
                .description_length = static_cast<ULONG>(description_length),
            };

            std::vector<std::byte> bytes(sizeof(entry) + description_length);
            std::memcpy(bytes.data(), &entry, sizeof(entry));
            if (description_length)
            {
                std::memcpy(bytes.data() + sizeof(entry), identity.description.data(), description_length);
            }

            return write_output_bytes(win_emu, c, bytes);
        }

        NTSTATUS write_zero_output(windows_emulator& win_emu, const io_device_context& context)
        {
            if (context.output_buffer && context.output_buffer_length)
            {
                std::vector<std::byte> output(context.output_buffer_length, std::byte{0});
                win_emu.emu().write_memory(context.output_buffer, output.data(), output.size());
            }

            write_io_information(context, context.output_buffer_length);
            return STATUS_SUCCESS;
        }

#ifdef OS_WINDOWS
        NTSTATUS ntstatus_from_win32_error(const DWORD error)
        {
            switch (error)
            {
            case ERROR_INSUFFICIENT_BUFFER:
                return STATUS_BUFFER_TOO_SMALL;
            case ERROR_MORE_DATA:
                return STATUS_BUFFER_OVERFLOW;
            case ERROR_FILE_NOT_FOUND:
            case ERROR_NOT_FOUND:
                return STATUS_NOT_FOUND;
            case ERROR_INVALID_PARAMETER:
                return STATUS_INVALID_PARAMETER;
            default:
                return STATUS_UNSUCCESSFUL;
            }
        }

        std::optional<NTSTATUS> forward_host_tcp_query(windows_emulator& win_emu, const io_device_context& c)
        {
            if (!c.input_buffer || !c.input_buffer_length)
            {
                return std::nullopt;
            }

            std::vector<std::uint8_t> input(c.input_buffer_length);
            if (!win_emu.emu().try_read_memory(c.input_buffer, input.data(), input.size()))
            {
                return std::nullopt;
            }

            std::vector<std::uint8_t> output(c.output_buffer_length);
            const auto output_buffer = output.empty() ? nullptr : output.data();
            DWORD bytes_returned = 0;

            const auto device =
                CreateFileW(LR"(\\.\Tcp)", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (device == INVALID_HANDLE_VALUE)
            {
                return std::nullopt;
            }

            const auto close_device = utils::finally([&] { CloseHandle(device); });
            const auto ok =
                DeviceIoControl(device, k_ioctl_tcp_query_information_ex, input.data(), static_cast<DWORD>(input.size()), output_buffer,
                                static_cast<DWORD>(output.size()), &bytes_returned, nullptr);
            const auto error = ok ? ERROR_SUCCESS : GetLastError();

            const auto bytes_to_write = std::min<std::size_t>(bytes_returned, output.size());
            if (c.output_buffer && bytes_to_write)
            {
                win_emu.emu().write_memory(c.output_buffer, output.data(), bytes_to_write);
            }
            write_io_information(c, bytes_to_write);
            win_emu.log.print(color::dark_gray, "--> Tcp host-forwarded query: status=0x%08lX bytes=%lu\n",
                              ok ? STATUS_SUCCESS : ntstatus_from_win32_error(error), bytes_returned);
            return ok ? STATUS_SUCCESS : ntstatus_from_win32_error(error);
        }
#endif

        std::optional<tcp_request_query_information_ex> read_tcp_query(windows_emulator& win_emu, const io_device_context& c)
        {
            if (!c.input_buffer || c.input_buffer_length < sizeof(tdi_object_id))
            {
                return std::nullopt;
            }

            tcp_request_query_information_ex request{};
            const auto bytes_to_read = std::min<size_t>(sizeof(request), c.input_buffer_length);
            if (!win_emu.emu().try_read_memory(c.input_buffer, &request, bytes_to_read))
            {
                return std::nullopt;
            }

            return request;
        }

        ULONG entity_type_for(const ULONG entity)
        {
            switch (entity)
            {
            case k_if_entity:
                return k_if_mib;
            case k_at_entity:
                return k_at_null;
            case k_cl_nl_entity:
                return k_cl_nl_ip;
            case k_co_tl_entity:
                return k_co_tl_tcp;
            case k_cl_tl_entity:
                return k_cl_tl_udp;
            default:
                return 0;
            }
        }

        NTSTATUS query_tcp_information(windows_emulator& win_emu, const io_device_context& c)
        {
            const auto request = read_tcp_query(win_emu, c);
            if (!request)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto& id = request->id;
            win_emu.log.print(color::dark_gray,
                              "--> Tcp query: entity=0x%lX/%lu class=0x%lX type=0x%lX id=0x%lX in=%lu out=%lu\n",
                              id.entity.entity, id.entity.instance, id.info_class, id.info_type, id.info_id, c.input_buffer_length,
                              c.output_buffer_length);

            if (id.entity.entity == k_generic_entity && id.info_class == k_info_class_generic && id.info_type == k_info_type_provider &&
                id.info_id == k_entity_list_id)
            {
                constexpr std::array entities{
                    tdi_entity_id{k_if_entity, 0},
                    tdi_entity_id{k_at_entity, 0},
                    tdi_entity_id{k_cl_nl_entity, 0},
                    tdi_entity_id{k_co_tl_entity, 0},
                    tdi_entity_id{k_cl_tl_entity, 0},
                };
                return write_output_array(win_emu, c, std::span<const tdi_entity_id>{entities});
            }

            if (id.info_class == k_info_class_generic && id.info_type == k_info_type_provider && id.info_id == k_entity_type_id)
            {
                const auto entity_type = entity_type_for(id.entity.entity);
                if (entity_type)
                {
                    return write_output(win_emu, c, entity_type);
                }
            }

            if (id.entity.entity == k_cl_nl_entity && id.info_class == k_info_class_protocol && id.info_type == k_info_type_provider &&
                id.info_id == k_ip_mib_stats_id)
            {
                const ip_snmp_info info{
                    .forwarding = 2,
                    .default_ttl = 128,
                    .interface_count = 1,
                    .address_count = 1,
                    .route_count = 1,
                };
                return write_output(win_emu, c, info);
            }

            if (id.entity.entity == k_cl_nl_entity && id.info_class == k_info_class_protocol && id.info_type == k_info_type_provider &&
                id.info_id == k_ip_mib_addrtable_entry_id)
            {
                const auto& identity = host_network_identity();
                const ip_address_entry entry{
                    .address = identity.address,
                    .interface_index = identity.interface_index,
                    .mask = identity.mask,
                    .broadcast_address = 1,
                    .reassembly_size = 65535,
                };
                return write_output(win_emu, c, entry);
            }

            if (id.entity.entity == k_if_entity && id.info_class == k_info_class_protocol && id.info_type == k_info_type_provider &&
                id.info_id == k_if_mib_stats_id)
            {
                const auto& identity = host_network_identity();
                win_emu.log.print(color::dark_gray,
                                  "--> Tcp IF row: index=%lu type=%lu ip=%u.%u.%u.%u mac=%02X:%02X:%02X:%02X:%02X:%02X\n",
                                  identity.interface_index, identity.interface_type, identity.address & 0xFF,
                                  (identity.address >> 8) & 0xFF, (identity.address >> 16) & 0xFF,
                                  (identity.address >> 24) & 0xFF, identity.physical_address[0], identity.physical_address[1],
                                  identity.physical_address[2], identity.physical_address[3], identity.physical_address[4],
                                  identity.physical_address[5]);
                return write_interface_entry(win_emu, c, identity);
            }

            return write_zero_output(win_emu, c);
        }

        struct transport_stub_device : stateless_device
        {
            NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& context) override
            {
                if (context.io_control_code == k_ioctl_tcp_query_information_ex)
                {
#ifdef OS_WINDOWS
                    if (win_emu.emulation_root.empty())
                    {
                        if (const auto status = forward_host_tcp_query(win_emu, context))
                        {
                            return *status;
                        }
                    }
#endif
                    return query_tcp_information(win_emu, context);
                }

                return write_zero_output(win_emu, context);
            }
        };
    }

    bool needs_32_bit_devices(const windows_emulator& win_emu)
    {
        return win_emu.process.is_wow64_process;
    }

    std::unique_ptr<io_device> create_device(const std::u16string_view device, const bool is_32_bit)
    {
        if (device == u"CNG"                    //
            || device == u"RasAcd"              //
            || device == u"PcwDrv"              //
            || device == u"SrpDevice"           //
            || device == u"DeviceApi\\CMApi"    //
            || device == u"DeviceApi\\CMNotify" //
            || device == u"ConDrv\\Server")
        {
            return std::make_unique<dummy_device>();
        }

        if (device == u"Nsi")
        {
            return create_network_store_interface();
        }

        if (device == u"Afd\\Endpoint")
        {
            return create_afd_endpoint(is_32_bit);
        }

        if (device == u"Afd\\AsyncConnectHlp")
        {
            return create_afd_async_connect_hlp(is_32_bit);
        }

        if (device == u"MountPointManager")
        {
            return create_mount_point_manager();
        }

        if (device == u"KsecDD")
        {
            return create_security_support_provider();
        }

        if (device == u"NamedPipe")
        {
            return std::make_unique<named_pipe>();
        }

        if (device == u"SogenGpu")
        {
            return create_gpu_bridge();
        }

        if (device == u"Tcp" || device == u"Tcp6" || device == u"Udp" || device == u"RawIp")
        {
            return std::make_unique<transport_stub_device>();
        }

        throw std::runtime_error("Unsupported device: " + u16_to_u8(device));
    }

    NTSTATUS io_device_container::io_control(windows_emulator& win_emu, const io_device_context& context)
    {
        this->assert_validity();
        win_emu.callbacks.on_ioctrl(*this->device_, this->device_name_, context.io_control_code);
        return this->device_->io_control(win_emu, context);
    }

    void io_device_container::work(windows_emulator& win_emu)
    {
        this->assert_validity();
        this->device_->work(win_emu);
    }

    void io_device_container::serialize_object(utils::buffer_serializer& buffer) const
    {
        this->assert_validity();

        buffer.write(this->is_32_bit_);
        buffer.write_string(this->device_name_);
        this->device_->serialize(buffer);
    }

    void io_device_container::deserialize_object(utils::buffer_deserializer& buffer)
    {
        buffer.read(this->is_32_bit_);
        buffer.read_string(this->device_name_);

        this->setup();
        this->device_->deserialize(buffer);
    }

} // namespace sogen
