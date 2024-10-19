cmake_minimum_required(VERSION 3.10)
project(SignatureProject)

# 设置C标准和C++标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-fcommon)
endif()

set(CMAKE_CXX_FLAGS "-std=c++17 -mfma")
add_compile_options(-mfma)
# 添加 sha3 子目录
add_subdirectory(sha3)


include_directories(${CMAKE_SOURCE_DIR}/include)

# 添加你的主项目源文件（假设在 src 目录下）
file(GLOB_RECURSE PROJECT_SOURCES "src/*.c" "src/*.cpp")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mpclmul -msse2")

# 创建可执行文件 (假设可执行文件名称为 my_project)
add_executable(my_project ${PROJECT_SOURCES})


target_compile_options(my_project PRIVATE -mavx2)

# 链接 sha3 库到你的可执行文件
target_link_libraries(my_project PRIVATE sha3)
