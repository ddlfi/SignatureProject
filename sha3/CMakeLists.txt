# 声明sha3子项目
project(sha3)


if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-fcommon)
endif()


# 获取当前目录下的所有源文件
file(GLOB SHA3_HEADERS
    "*.h"
    "armv8a-neon/*.h"
    "avx2/*.h"
    "opt64/*.h"
    "plain32/*.h"
)

file(GLOB SHA3_SOURCES
    "*.c"
    "armv8a-neon/*.s"
    "armv8a-neon/*.c"
    "avx2/*.s"
    "avx2/*.c"
    "opt64/*.c"
    "plain32/*.c"
)

# 创建一个静态库
add_library(sha3 STATIC ${SHA3_SOURCES} ${SHA3_HEADERS})

# 设置 include 目录
target_include_directories(sha3 PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/armv8a-neon
    ${CMAKE_CURRENT_SOURCE_DIR}/avx2
    ${CMAKE_CURRENT_SOURCE_DIR}/opt64
    ${CMAKE_CURRENT_SOURCE_DIR}/plain32
    ../include
)