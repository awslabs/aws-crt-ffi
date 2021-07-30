cmake_minimum_required(VERSION 3.1)
project(aws-crt-ffi C)
message(STATUS "CMake ${CMAKE_VERSION}")

option(BUILD_SHARED_LIBS "Build shared library for FFI: default: ON" ON)

if (POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW) # Enable LTO/IPO if available in the compiler
endif()

if (DEFINED CMAKE_PREFIX_PATH)
    file(TO_CMAKE_PATH "${CMAKE_PREFIX_PATH}" CMAKE_PREFIX_PATH)
endif()

if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

if (UNIX AND NOT APPLE)
    set(FIND_LIBRARY_USE_LIB64_PATHS true)
endif()

# This is required in order to append /lib/cmake to each element in CMAKE_PREFIX_PATH
set(AWS_MODULE_DIR "/${CMAKE_INSTALL_LIBDIR}/cmake")
string(REPLACE ";" "${AWS_MODULE_DIR};" AWS_MODULE_PATH "${CMAKE_PREFIX_PATH}${AWS_MODULE_DIR}")
# Append that generated list to the module search path
list(APPEND CMAKE_MODULE_PATH ${AWS_MODULE_PATH})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/crt/aws-c-common/cmake")

include(AwsFindPackage)

set(IN_SOURCE_BUILD ON)
set(SEARCH_LIBCRYPTO OFF CACHE BOOL "Let S2N use libcrypto from AWS-LC.")

# Don't compile tests in subdirectories.
# Turn off using `option` instead of `set`, or CTest will declare
# it as an option later and override the existing variable.
set(BUILD_TESTING OFF)

# Disable BUILD_SHARED_LIBS for all CRT libs
set(SHARED_FFI_LIB ${BUILD_SHARED_LIBS})
set(BUILD_SHARED_LIBS OFF)

# CRT Libraries
add_subdirectory(crt/aws-c-common)
if (UNIX AND NOT APPLE)
    if (NOT (CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64) AND
        NOT (CMAKE_SYSTEM_PROCESSOR STREQUAL armv7l))
        set(DISABLE_PERL ON)
    endif()
    set(DISABLE_GO ON)
    set(SEARCH_LIBCRYPTO OFF)
    set(BUILD_LIBSSL OFF)
    add_subdirectory(crt/aws-lc)
    add_subdirectory(crt/s2n)
endif()
add_subdirectory(crt/aws-c-io)
add_subdirectory(crt/aws-c-cal)
add_subdirectory(crt/aws-c-compression)
add_subdirectory(crt/aws-c-http)
add_subdirectory(crt/aws-c-auth)
add_subdirectory(crt/aws-c-event-stream)
add_subdirectory(crt/aws-checksums)

# Restore BUILD_SHARED_LIBS for this project
set(BUILD_SHARED_LIBS ${SHARED_FFI_LIB})

include(AwsCFlags)
include(AwsSharedLibSetup)

file(GLOB AWS_CRT_SRC "src/*.h" "src/*.c")

add_library(${PROJECT_NAME} ${AWS_CRT_SRC})
aws_set_common_properties(${PROJECT_NAME})
aws_prepare_shared_lib_exports(${PROJECT_NAME})

aws_use_package(aws-c-common)
aws_use_package(aws-c-io)
aws_use_package(aws-c-cal)
aws_use_package(aws-c-compression)
aws_use_package(aws-c-http)
aws_use_package(aws-c-auth)
aws_use_package(aws-c-event-stream)
aws_use_package(aws-checksums)

aws_add_sanitizers(${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME} PRIVATE ${DEP_AWS_LIBS})
aws_set_common_properties(${PROJECT_NAME})

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/"
        COMPONENT Development)
