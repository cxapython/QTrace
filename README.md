# QTrace

### 准备工作:
adb设置setenforce 0

libs目录里面放个libfrida-gum.a和libQBDI.a

>其中libQBDI.a在项目qbdi的QBDI-0.12.1-android-AARCH64.tar.gz里面,libfrida-gum.a在frida的frida-gum-devkit-16.5.9-android-arm64.tar.xz
里面

### Clion里的配置
```
-DCMAKE_TOOLCHAIN_FILE=/Users/chennan/Library/Android/sdk/ndk/27.1.12297006/build/cmake/android.toolchain.cmake -DCMAKE_ANDROID_NDK=/Users/chennan/Library/Android/sdk/ndk/27.1.12297006 -DANDROID_ABI=arm64-v8a -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=28 -DCMAKE_C_FLAGS="" -DCMAKE_CXX_FLAGS="" -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a
```