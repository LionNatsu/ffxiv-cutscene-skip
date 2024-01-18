cmake_minimum_required (VERSION 3.20)

project (csskip)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_executable(csskip)
target_sources(csskip PRIVATE csskip.cpp csskip.rc)
target_include_directories(csskip PRIVATE third_party/include)
target_link_options(csskip PRIVATE /MANIFEST:NO)

install(TARGETS csskip)
