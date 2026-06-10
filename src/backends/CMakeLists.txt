if(SOGEN_ENABLE_UNICORN_BACKEND)
  add_subdirectory(unicorn-emulator)
endif()

if (SOGEN_ENABLE_RUST)
  add_subdirectory(icicle-emulator)
endif()

if (NOT MINGW AND MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_subdirectory(whp-emulator)
endif()
