cmake_minimum_required(VERSION 3.16)

project(vdfrsa_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(vdfrsa_native SHARED openssl_vdf.c)
target_include_directories(vdfrsa_native PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vdfrsa_native PRIVATE OpenSSL::Crypto)
