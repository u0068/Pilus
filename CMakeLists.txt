cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 17)

project(Pilus)

add_subdirectory(external/SFML)

add_subdirectory(external/zlib)

add_subdirectory(external/zlib/contrib/minizip)

add_executable(Pilus modloader_main.cpp modloader.h)

target_link_libraries(Pilus PRIVATE SFML::Graphics)
target_link_libraries(Pilus PRIVATE MINIZIP::minizipstatic)
