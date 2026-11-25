cmake_minimum_required(VERSION 4.3)

project(escrow
  VERSION 0.1.0
  SPDX_LICENSE "MIT"
  DESCRIPTION "Agents propose, humans sign."
  HOMEPAGE_URL "https://github.com/wasdhjklxyz/escrow"
  LANGUAGES C)

include(GNUInstallDirs)

if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_C_STANDARD 23)
  set(CMAKE_C_STANDARD_REQUIRED ON)
  set(CMAKE_C_EXTENSIONS OFF)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()

add_library(escrow_common INTERFACE)
add_library(escrow::common ALIAS escrow_common)
target_compile_definitions(escrow_common INTERFACE _GNU_SOURCE)
target_compile_options(escrow_common
  INTERFACE -Wall -Wextra -Wpedantic -Werror
    $<$<CONFIG:Debug>:-Og -U_FORTIFY_SOURCE -fsanitize=address,undefined>)
target_link_options(escrow_common
  INTERFACE $<$<CONFIG:Debug>:-fsanitize=address,undefined>)

add_subdirectory(src)
