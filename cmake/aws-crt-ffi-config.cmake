include(CMakeFindDependencyMacro)

if (UNIX AND NOT APPLE)
    find_dependency(s2n)
endif()

find_dependency(aws-c-common)
find_dependency(aws-c-sdkutils)
find_dependency(aws-c-cal)
find_dependency(aws-c-io)
find_dependency(aws-c-http)
find_dependency(aws-c-auth)
find_dependency(aws-c-event-stream)
find_dependency(aws-c-compression)
find_dependency(aws-checksums)

include(${CMAKE_CURRENT_LIST_DIR}/shared/@PROJECT_NAME@-targets.cmake)
