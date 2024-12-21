cmake_minimum_required(VERSION 3.9)
project(aws-crt-ffi C)
message(STATUS "CMake ${CMAKE_VERSION}")

option(BUILD_DEPS "Builds aws common runtime dependencies as part of build. Turn off if you want to control your dependency chain." ON)
option(BUILD_SHARED_LIBS "Build shared library for FFI: default: ON" ON)

if (BUILD_DEPS)
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
        include(AwsPrebuildDependency)
        if (NOT USE_OPENSSL)
            set(AWSLC_CMAKE_ARGUMENTS
                -DDISABLE_GO=ON  # Build without using Go, we don't want the extra dependency
                -DDISABLE_PERL=ON  # Build without using Perl, we don't want the extra dependency
                -DBUILD_LIBSSL=OFF  # Don't need libssl, only need libcrypto
                -DBUILD_TESTING=OFF
            )
            if(CMAKE_C_COMPILER_ID MATCHES "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "5.0")
                # Disable AVX512 on old GCC that not supports it.
                list(APPEND AWSLC_CMAKE_ARGUMENTS -DMY_ASSEMBLER_IS_TOO_OLD_FOR_512AVX=ON)
            endif()

            # s2n-tls uses libcrypto during its configuration, so we need to prebuild aws-lc.
            aws_prebuild_dependency(
                DEPENDENCY_NAME AWSLC
                SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/crt/aws-lc
                CMAKE_ARGUMENTS ${AWSLC_CMAKE_ARGUMENTS}
            )
        endif()
        # prebuild s2n-tls.
        aws_prebuild_dependency(
            DEPENDENCY_NAME S2N
            SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/crt/s2n
            CMAKE_ARGUMENTS
                -DUNSAFE_TREAT_WARNINGS_AS_ERRORS=OFF
                -DBUILD_TESTING=OFF
        )
    endif()
    add_subdirectory(crt/aws-c-sdkutils)
    add_subdirectory(crt/aws-c-io)
    add_subdirectory(crt/aws-c-cal)
    add_subdirectory(crt/aws-c-compression)
    add_subdirectory(crt/aws-c-http)
    add_subdirectory(crt/aws-c-auth)
    add_subdirectory(crt/aws-c-event-stream)
    add_subdirectory(crt/aws-checksums)
else()
    # this is required so we can use aws-c-common's CMake modules
    find_package(aws-c-common REQUIRED)

    include(AwsFindPackage)
    set(IN_SOURCE_BUILD OFF)
endif()

# Restore BUILD_SHARED_LIBS for this project
set(BUILD_SHARED_LIBS ${SHARED_FFI_LIB})

include(AwsCFlags)
include(AwsSharedLibSetup)
include(AwsSanitizers)
include(GNUInstallDirs)

file(GLOB AWS_CRT_SRC "src/*.h" "src/*.c")

add_library(${PROJECT_NAME} ${AWS_CRT_SRC})
aws_set_common_properties(${PROJECT_NAME})
aws_prepare_shared_lib_exports(${PROJECT_NAME})

aws_use_package(aws-c-common)
aws_use_package(aws-c-sdkutils)
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
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/"
        COMPONENT Development)
