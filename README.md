# QTrace

### 准备工作:
adb设置setenforce 0

在项目的最外层创建libs目录里面放个libfrida-gum.a和libQBDI.a。

>其中libQBDI.a在项目qbdi的QBDI-0.12.1-android-AARCH64.tar.gz里面,libfrida-gum.a在frida的frida-gum-devkit-16.5.9-android-arm64.tar.xz
里面

### Clion里的配置
```
-DCMAKE_TOOLCHAIN_FILE=/Users/chennan/Library/Android/sdk/ndk/27.1.12297006/build/cmake/android.toolchain.cmake -DCMAKE_ANDROID_NDK=/Users/chennan/Library/Android/sdk/ndk/27.1.12297006 -DANDROID_ABI=arm64-v8a -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=28 -DCMAKE_C_FLAGS="" -DCMAKE_CXX_FLAGS="" -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a
```

## 功能说明

这个项目的核心目标是：用 Frida-Gum 把目标函数 Hook 住，然后在 replacement 里把当前寄存器上下文同步给 QBDI VM，再用 QBDI 做指令级 Trace（反汇编 + 可选符号 + 每条指令的寄存器变化），最终把 Trace 结果写到文件，便于按 trace 文件反推算法逻辑。

当前实现的特点：

- Trace 默认输出每条指令的反汇编 + 符号信息 + 寄存器变化（Δ before -> after）
- Trace 默认只记录前 200 条指令（可配置）
- Hook 触发一次后会 revert（保持你原来“一次性 trace”的行为）

## 导出接口

动态库导出符号（可被 Frida 直接调用）：

- `void gum_handle(void *target_addr)`
- `void qtrace_set_options(uint32_t flags, uint64_t max_instructions, uint32_t log_every, bool instrument_all_executable)`
- `void qtrace_set_module_filter(const char *module_substr)`
- `void qtrace_set_output_path(const char *path)`

### Trace Flags（flags 位掩码）

- `1`  `TRACE_DISASM`：输出反汇编
- `2`  `TRACE_SYMBOL`：输出 module/symbol/offset
- `4`  `TRACE_GPR`：输出寄存器变化（Δ before->after）
- `8`  `TRACE_MEM`：输出内存访问（需要 QBDI recordMemoryAccess）
- `16` `TRACE_BB`：输出 basic block 进入/退出信息

推荐默认 flags：

- `TRACE_DISASM | TRACE_SYMBOL | TRACE_GPR` = `1 | 2 | 4` = `7`

### 输出文件

`qtrace_set_output_path("/data/local/tmp/qtrace.trace")` 用于开启文件输出。

- path 为空或 NULL 会关闭文件输出
- 输出会同时写 logcat + 文件（logcat 可能被系统截断，但文件是完整的）

## Trace 输出格式

每条指令会输出 1 行指令 + 1 行寄存器变化：

- 指令行：
  - `#<序号> <address> <module>!<symbol>+<offset> | <disasm>`
- 寄存器变化行：
  - `  Δ x0:0x...->0x... x1:0x...->0x... ... pc:0x...->0x...`

其中寄存器变化行只输出“发生变化”的寄存器（pc 基本每条都会变化）。

如果开启 `TRACE_MEM`，会额外输出该条指令的内存访问行（可能多行）：

- `  memR addr=0x... size=8 value=0x... flags=0`

## Frida 使用示例

下面示例演示：加载 `libQTrace.so` 后，配置 trace 输出到文件，并 Hook 某个函数入口地址。

```js
// 需要你自行找到目标函数地址 targetAddr
// 例如：Module.findExportByName("libxxx.so", "target_func")

function callExport(moduleName, exportName, retType, argTypes, args) {
  const addr = Module.findExportByName(moduleName, exportName);
  if (addr === null) throw new Error("missing export: " + exportName);
  const fn = new NativeFunction(addr, retType, argTypes);
  return fn.apply(null, args);
}

const qtrace = "libQTrace.so";
const TRACE_DISASM = 1;
const TRACE_SYMBOL = 2;
const TRACE_GPR = 4;

callExport(qtrace, "qtrace_set_output_path", "void", ["pointer"], [
  Memory.allocUtf8String("/data/local/tmp/qtrace.trace"),
]);

callExport(qtrace, "qtrace_set_options", "void", ["uint", "ulong", "uint", "bool"], [
  TRACE_DISASM | TRACE_SYMBOL | TRACE_GPR,
  500,   // max_instructions
  1,     // log_every
  true,  // instrument_all_executable
]);

// 可选：只记录特定 module（按子串匹配 analysis->moduleName）
// callExport(qtrace, "qtrace_set_module_filter", "void", ["pointer"], [
//   Memory.allocUtf8String("libxxx.so"),
// ]);

callExport(qtrace, "gum_handle", "void", ["pointer"], [
  targetAddr,
]);
```

## 编译与产物

```bash
cmake -S . -B build
cmake --build build -j
```

默认产物输出到：

- `./libs/arm64-v8a/libQTrace.so`

## 常见问题

- 文件写不出来：
  - 目标进程权限不足时，优先写 `/data/data/<package>/files/xxx.trace` 或者确保具备写入目标路径权限
- Trace 太多太慢：
  - 降低 `max_instructions`
  - 设置 `log_every`（例如 5 表示每 5 条输出一次）
  - 关闭 `TRACE_SYMBOL` 或 `TRACE_MEM`
