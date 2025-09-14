cmake_minimum_required(VERSION 3.14)
project(md5-lib VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


add_library(md5_lib STATIC
  src/md5.cpp
)

target_include_directories(md5_lib PUBLIC
  # For consumers inside this build tree use the source dir.
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  # For consumers of the installed package, use the installed include dir.
  $<INSTALL_INTERFACE:include>
)

# --- Google Test Integration ---
cmake_policy(SET CMP0135 NEW)  # CMP0135: Set DOWNLOAD_EXTRACT_TIMESTAMP

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(md5_test
  tests/md5_test.cpp
)
target_link_libraries(md5_test PRIVATE
  md5_lib
  GTest::gtest_main
)
include(GoogleTest)
gtest_discover_tests(md5_test)


# --- Installation Rules ---
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(FILES include/md5.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(TARGETS md5_lib
  EXPORT md5-lib-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(EXPORT md5-lib-targets
  FILE md5-lib-targets.cmake
  NAMESPACE md5_lib::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/md5-lib
)

configure_package_config_file(
  "cmake/md5-lib-config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/md5-lib-config.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/md5-lib"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/md5-lib-config.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/md5-lib"
)