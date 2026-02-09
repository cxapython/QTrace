cmake_minimum_required(VERSION 4.1)
# 设置交叉编译工具链；要放在project上方，否则不知道这个设置
set(ANDROID_NDK "/Users/chennan/Library/Android/sdk/ndk/27.1.12297006")

set(CMAKE_TOOLCHAIN_FILE ${ANDROID_NDK}/build/cmake/android.toolchain.cmake)

# 设置Android相关变量
set(CMAKE_SYSTEM_NAME ANDROID)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM 28)

set(CMAKE_ANDROID_NDK ${ANDROID_NDK})
set(CMAKE_ANDROID_ARCH_ABI ${ANDROID_ABI})
set(CMAKE_SYSTEM_VERSION ${ANDROID_PLATFORM})

set(BUILD_SHARED_LIBS ON)
project(QTrace)
set(CMAKE_CXX_STANDARD 17)

# 关键修改：STATIC（静态库）改成 SHARED（动态库）
# Android 平台的动态库后缀是 .so
add_library(QTrace SHARED library.cpp)

# 可选：指定库的输出路径（方便找到so文件）
set_target_properties(QTrace PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/libs/arm64-v8a
)

# 头文件
include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        ${CMAKE_CURRENT_SOURCE_DIR}/include/QBDI
)

# libs
target_link_libraries(${CMAKE_PROJECT_NAME}
        ${PROJECT_SOURCE_DIR}/libs/libfrida-gum.a
        ${PROJECT_SOURCE_DIR}/libs/libQBDI.a

        android
        log)