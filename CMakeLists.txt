cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "pcapreader")
project(${PROJECT_NAME})

# Specifying the C++ Standard and flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-O2 -Wall -Wextra -pedantic")

aux_source_directory("src" core_src)
add_executable(${PROJECT_NAME} ${core_src})
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

install(TARGETS ${PROJECT_NAME})
