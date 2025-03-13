cmake_minimum_required(VERSION 3.10)
project(wazuh_filtering_module)

# Include Wazuh source directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/shared
    ${CMAKE_SOURCE_DIR}/src/headers
)

# Compile shared utilities you need
add_library(wazuh_minimal_shared SHARED
    ${CMAKE_SOURCE_DIR}/src/shared/debug_op.c
    ${CMAKE_SOURCE_DIR}/src/shared/mq_op.c
    # Other necessary shared files
)

# Compile your module
add_executable(wazuh_filtering
    filtering_module.c
    # Other source files
)

target_link_libraries(wazuh_filtering wazuh_minimal_shared pthread)