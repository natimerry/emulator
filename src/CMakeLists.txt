add_subdirectory(common)
add_subdirectory(emulator)
add_subdirectory(gdb-stub)
add_subdirectory(backends)
add_subdirectory(windows-emulator)
add_subdirectory(windows-gdb-stub)

if (NOT MOMO_BUILD_AS_LIBRARY)
    add_subdirectory(analyzer)
    add_subdirectory(fuzzing-engine)
    add_subdirectory(fuzzer)
    add_subdirectory(windows-emulator-test)
    if(WIN32)
        momo_add_subdirectory_and_get_targets("tools" TOOL_TARGETS)
        momo_targets_set_folder("tools" ${TOOL_TARGETS})

        momo_add_subdirectory_and_get_targets("samples" SAMPLE_TARGETS)
        momo_targets_set_folder("samples" ${SAMPLE_TARGETS})
    endif()
endif()
