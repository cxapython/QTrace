#include <android/log.h>
#include "include/frida-gum.h"
#include "include/QBDI.h"
#include "include/QBDI/State.h"
#include "include/QBDI/VM.h"
#include "include/QBDI/VM_C.h"
#include <atomic>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <time.h>
#include <vector>
#define LOG_TAG "Qtrace"
#define LOGS(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##__VA_ARGS__);

namespace {

enum TraceFlags : uint32_t {
    TRACE_DISASM = 1u << 0,
    TRACE_SYMBOL = 1u << 1,
    TRACE_GPR = 1u << 2,
    TRACE_MEM = 1u << 3,
    TRACE_BB = 1u << 4,
};

struct TraceConfigSnapshot {
    uint32_t flags;
    uint64_t maxInstructions;
    uint32_t logEvery;
    bool instrumentAllExecutable;
    bool enableModuleFilter;
    char moduleFilter[128];
    bool enableFileOutput;
    char outputPath[256];
};

struct GlobalTraceConfig {
    std::atomic<uint32_t> flags{TRACE_DISASM | TRACE_SYMBOL | TRACE_GPR};
    std::atomic<uint64_t> maxInstructions{200};
    std::atomic<uint32_t> logEvery{1};
    std::atomic<bool> instrumentAllExecutable{true};
    std::atomic<bool> enableModuleFilter{false};
    std::atomic<bool> enableFileOutput{false};
    std::mutex moduleFilterMutex;
    char moduleFilter[128]{0};
    std::mutex outputPathMutex;
    char outputPath[256]{0};

    TraceConfigSnapshot snapshot() {
        TraceConfigSnapshot s{};
        s.flags = flags.load(std::memory_order_relaxed);
        s.maxInstructions = maxInstructions.load(std::memory_order_relaxed);
        s.logEvery = logEvery.load(std::memory_order_relaxed);
        s.instrumentAllExecutable = instrumentAllExecutable.load(std::memory_order_relaxed);
        s.enableModuleFilter = enableModuleFilter.load(std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(moduleFilterMutex);
            std::memcpy(s.moduleFilter, moduleFilter, sizeof(moduleFilter));
        }
        s.enableFileOutput = enableFileOutput.load(std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(outputPathMutex);
            std::memcpy(s.outputPath, outputPath, sizeof(outputPath));
        }
        return s;
    }
};

static GlobalTraceConfig g_traceConfig;

static GumInterceptor *g_interceptor = nullptr;
static void *g_target_addr = nullptr;
static void *g_original_entry = nullptr;

static inline uint64_t now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

static bool module_match(const TraceConfigSnapshot &cfg, const QBDI::InstAnalysis *analysis) {
    if (!cfg.enableModuleFilter) {
        return true;
    }
    if (analysis == nullptr || analysis->moduleName == nullptr) {
        return false;
    }
    return std::strstr(analysis->moduleName, cfg.moduleFilter) != nullptr;
}

struct TraceContext {
    TraceConfigSnapshot cfg;
    uint64_t instSeen{0};
    uint64_t instLogged{0};
    uint64_t startNs{0};
    QBDI::GPRState preGpr{};
    bool hasPreGpr{false};
    FILE *out{nullptr};
};

static void trace_emit(TraceContext *ctx, const char *fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    LOGS("%s", buf);
    if (ctx != nullptr && ctx->out != nullptr) {
        fputs(buf, ctx->out);
        fputc('\n', ctx->out);
    }
}

static void emit_gpr_diffs_line(TraceContext *ctx, const QBDI::GPRState &before, const QBDI::GPRState &after) {
    char buf[8192];
    size_t pos = 0;

    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Δ");

    char name[8];
    for (int i = 0; i < 29; i++) {
        const auto b = QBDI_GPR_GET((&before), i);
        const auto a = QBDI_GPR_GET((&after), i);
        if (b == a) {
            continue;
        }
        snprintf(name, sizeof(name), "x%d", i);
        pos += snprintf(buf + pos, sizeof(buf) - pos, " %s:%#" PRIx64 "->%#" PRIx64, name, b, a);
        if (pos >= sizeof(buf)) {
            break;
        }
    }

    if (before.x29 != after.x29) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, " fp:%#" PRIx64 "->%#" PRIx64, before.x29, after.x29);
    }
    if (before.lr != after.lr) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, " lr:%#" PRIx64 "->%#" PRIx64, before.lr, after.lr);
    }
    if (before.sp != after.sp) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, " sp:%#" PRIx64 "->%#" PRIx64, before.sp, after.sp);
    }
    if (before.pc != after.pc) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, " pc:%#" PRIx64 "->%#" PRIx64, before.pc, after.pc);
    }
    if (before.nzcv != after.nzcv) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, " nzcv:%#" PRIx64 "->%#" PRIx64, before.nzcv, after.nzcv);
    }

    trace_emit(ctx, "%s", buf);
}

static void log_mem_access(TraceContext *ctx, QBDI::VM *vm) {
    if (vm == nullptr) {
        return;
    }
    const auto acc = vm->getInstMemoryAccess();
    for (const auto &a : acc) {
        const char *t = (a.type == QBDI::MEMORY_READ) ? "R" : (a.type == QBDI::MEMORY_WRITE) ? "W" : "RW";
        trace_emit(ctx, "  mem%s addr=%#" PRIx64 " size=%u value=%#" PRIx64 " flags=%u",
                   t, a.accessAddress, static_cast<unsigned>(a.size), a.value, static_cast<unsigned>(a.flags));
    }
}

QBDI::VMAction preInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    (void) vm;
    (void) fprState;
    auto *ctx = static_cast<TraceContext *>(data);
    if (ctx == nullptr || gprState == nullptr) {
        return QBDI::VMAction::CONTINUE;
    }
    ctx->preGpr = *gprState;
    ctx->hasPreGpr = true;
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction postInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    (void) fprState;
    auto *ctx = static_cast<TraceContext *>(data);
    if (ctx == nullptr) {
        return QBDI::VMAction::CONTINUE;
    }

    ctx->instSeen++;

    if (ctx->instSeen > ctx->cfg.maxInstructions) {
        return QBDI::VMAction::CONTINUE;
    }

    if (ctx->cfg.logEvery != 0 && (ctx->instSeen % ctx->cfg.logEvery) != 0) {
        return QBDI::VMAction::CONTINUE;
    }

    QBDI::AnalysisType analysisType = QBDI::ANALYSIS_INSTRUCTION;
    if ((ctx->cfg.flags & TRACE_DISASM) != 0) {
        analysisType = analysisType | QBDI::ANALYSIS_DISASSEMBLY;
    }
    if ((ctx->cfg.flags & TRACE_SYMBOL) != 0) {
        analysisType = analysisType | QBDI::ANALYSIS_SYMBOL;
    }

    const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(analysisType);
    if (!module_match(ctx->cfg, analysis)) {
        return QBDI::VMAction::CONTINUE;
    }

    ctx->instLogged++;

    if (analysis != nullptr) {
        const char *mod = (analysis->moduleName != nullptr) ? analysis->moduleName : "?";
        const char *sym = (analysis->symbolName != nullptr) ? analysis->symbolName : "?";
        const char *dis = (analysis->disassembly != nullptr) ? analysis->disassembly : "?";

        if ((ctx->cfg.flags & TRACE_SYMBOL) != 0) {
            trace_emit(ctx, "#%" PRIu64 " %#" PRIx64 " %s!%s+%u | %s",
                       ctx->instSeen, analysis->address, mod, sym, analysis->symbolOffset, dis);
        } else {
            trace_emit(ctx, "#%" PRIu64 " %#" PRIx64 " | %s", ctx->instSeen, analysis->address, dis);
        }

        if (((ctx->cfg.flags & TRACE_GPR) != 0) && gprState != nullptr && ctx->hasPreGpr) {
            emit_gpr_diffs_line(ctx, ctx->preGpr, *gprState);
        }

        if ((ctx->cfg.flags & TRACE_MEM) != 0) {
            log_mem_access(ctx, vm);
        }

        if (analysis->isReturn) {
            trace_emit(ctx, "  <return>");
        } else if (analysis->isCall) {
            trace_emit(ctx, "  <call>");
        }
    }

    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction onBasicBlock(QBDI::VMInstanceRef vm, const QBDI::VMState *vmState, QBDI::GPRState *gprState,
                           QBDI::FPRState *fprState, void *data) {
    (void) vm;
    (void) gprState;
    (void) fprState;
    auto *ctx = static_cast<TraceContext *>(data);
    if (ctx == nullptr || vmState == nullptr) {
        return QBDI::VMAction::CONTINUE;
    }
    if ((ctx->cfg.flags & TRACE_BB) == 0) {
        return QBDI::VMAction::CONTINUE;
    }
    trace_emit(ctx, "BB %#" PRIx64 " -> %#" PRIx64 " (seq %#" PRIx64 " -> %#" PRIx64 ") event=%u",
               vmState->basicBlockStart, vmState->basicBlockEnd, vmState->sequenceStart, vmState->sequenceEnd,
               static_cast<unsigned>(vmState->event));
    return QBDI::VMAction::CONTINUE;
}

}

/* 功能：寄存器状态同步函数
 * 将frida-gum 和qbdi的上下文寄存器进行同步，可以F->Q，也可以Q->F
 * */
void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q) {
    if (F2Q) {
        for (int i = 0; i < 29; i++) {
            QBDI_GPR_SET(state, i, cpu->x[i]);
        }

        state->lr = cpu->lr;
        state->sp = cpu->sp;
        state->pc = cpu->pc;
        state->x29 = cpu->fp;
        state->nzcv = cpu->nzcv;
    } else {
        for (int i = 0; i < 29; i++) {
            cpu->x[i] = QBDI_GPR_GET(state, i);
        }

        cpu->fp = state->x29;
        cpu->lr = state->lr;
        cpu->sp = state->sp;
        cpu->pc = state->pc;
        cpu->nzcv = state->nzcv;
    }
}

QBDI::VM vm_init(void *address, TraceContext *traceCtx) {
    QBDI::VM qvm{}; // 实例化
    void *data = traceCtx;

    // 注册后指令回调，用于打印机器码
    qvm.addCodeCB(QBDI::PREINST, preInstruction, data, QBDI::PRIORITY_DEFAULT);
    qvm.addCodeCB(QBDI::POSTINST, postInstruction, data, QBDI::PRIORITY_DEFAULT);

    if (traceCtx != nullptr && (traceCtx->cfg.flags & TRACE_BB) != 0) {
        qvm.addVMEventCB(QBDI::VMEvent::BASIC_BLOCK_ENTRY | QBDI::VMEvent::BASIC_BLOCK_EXIT, onBasicBlock, data);
    }

    if (traceCtx != nullptr && (traceCtx->cfg.flags & TRACE_MEM) != 0) {
        qvm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    }

    if (traceCtx != nullptr && traceCtx->cfg.instrumentAllExecutable) {
        qvm.instrumentAllExecutableMaps();
    } else {
        bool ok = false;
        if (g_target_addr != nullptr) {
            ok = qvm.addInstrumentedModuleFromAddr(static_cast<QBDI::rword>(reinterpret_cast<uintptr_t>(g_target_addr)));
        }
        if (address != nullptr) {
            ok = qvm.addInstrumentedModuleFromAddr(static_cast<QBDI::rword>(reinterpret_cast<uintptr_t>(address))) || ok;
        }
        if (!ok) {
            qvm.instrumentAllExecutableMaps();
        }
    }

    return qvm;
}

QBDI::rword replace_func() {
    LOGS("replace called");

    auto context = (GumInvocationContext *) gum_interceptor_get_current_invocation();
    // 从 Frida 拿到当前函数调用信息（参数、寄存器、原函数地址等上下文）
    auto interceptor = (GumInterceptor *) gum_invocation_context_get_replacement_data(context); // 拿到 interceptor 本体

    gum_interceptor_revert(interceptor, context->function); // 暂时取消 Hook， 恢复函数
    gum_interceptor_flush(interceptor); // 立即执行 ：暂时取消 Hook， 恢复函数

    TraceContext traceCtx{};
    traceCtx.cfg = g_traceConfig.snapshot();
    traceCtx.startNs = now_ns();
    if (traceCtx.cfg.enableFileOutput && traceCtx.cfg.outputPath[0] != '\0') {
        traceCtx.out = fopen(traceCtx.cfg.outputPath, "a");
        if (traceCtx.out != nullptr) {
            setvbuf(traceCtx.out, nullptr, _IOLBF, 0);
        }
    }

    auto qvm = vm_init(context->function, &traceCtx);

    // 同步 ：Frida 通用寄存器 -> qbdi 通用寄存器
    auto state = qvm.getGPRState();
    syn_reg_gum(context->cpu_context, state, true);

    /*
     * 切换到 QBDI 私有栈   state
     * 跳到原函数入口      context->function
     * 完整执行函数
     * 把返回值拿出来      ret
     */
    QBDI::rword ret;
    qvm.switchStackAndCall(&ret, (QBDI::rword) context->function, {}, 0x10000);

    // 同步 ：qbdi 通用寄存器 -> Frida 通用寄存器
    syn_reg_gum(context->cpu_context, state, false);

    const uint64_t costNs = now_ns() - traceCtx.startNs;
    trace_emit(&traceCtx, "trace summary: seen=%" PRIu64 " logged=%" PRIu64 " cost=%.3fms",
               traceCtx.instSeen, traceCtx.instLogged, static_cast<double>(costNs) / 1000000.0);

    if (traceCtx.out != nullptr) {
        fflush(traceCtx.out);
        fclose(traceCtx.out);
        traceCtx.out = nullptr;
    }

    LOGS("replace end");
    return ret;
}

extern "C" {
__attribute__((visibility("default"))) void qtrace_set_options(uint32_t flags, uint64_t max_instructions, uint32_t log_every,
                                                               bool instrument_all_executable) {
    g_traceConfig.flags.store(flags, std::memory_order_relaxed);
    g_traceConfig.maxInstructions.store(max_instructions, std::memory_order_relaxed);
    g_traceConfig.logEvery.store(log_every, std::memory_order_relaxed);
    g_traceConfig.instrumentAllExecutable.store(instrument_all_executable, std::memory_order_relaxed);
}

__attribute__((visibility("default"))) void qtrace_set_module_filter(const char *module_substr) {
    if (module_substr == nullptr || module_substr[0] == '\0') {
        g_traceConfig.enableModuleFilter.store(false, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(g_traceConfig.moduleFilterMutex);
        g_traceConfig.moduleFilter[0] = '\0';
        return;
    }
    g_traceConfig.enableModuleFilter.store(true, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(g_traceConfig.moduleFilterMutex);
    std::strncpy(g_traceConfig.moduleFilter, module_substr, sizeof(g_traceConfig.moduleFilter) - 1);
    g_traceConfig.moduleFilter[sizeof(g_traceConfig.moduleFilter) - 1] = '\0';
}

__attribute__((visibility("default"))) void qtrace_set_output_path(const char *path) {
    if (path == nullptr || path[0] == '\0') {
        g_traceConfig.enableFileOutput.store(false, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(g_traceConfig.outputPathMutex);
        g_traceConfig.outputPath[0] = '\0';
        return;
    }
    g_traceConfig.enableFileOutput.store(true, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(g_traceConfig.outputPathMutex);
    std::strncpy(g_traceConfig.outputPath, path, sizeof(g_traceConfig.outputPath) - 1);
    g_traceConfig.outputPath[sizeof(g_traceConfig.outputPath) - 1] = '\0';
}

__attribute__((visibility("default"))) void gum_handle(void *target_addr) {
    LOGS("HOOK REPLACE start, target_addr: %p", target_addr);

    // 初始化Gum运行环境
    gum_init();

    // 测试Gum库是否正常工作
    GumThreadId thread_id = gum_process_get_current_thread_id();
    LOGS("gum_process_get_current_thread_id : %lu", thread_id);

    // 检查目标地址是否有效
    if (target_addr == nullptr) {
        LOGS("Error: target_addr == nullptr");
        return;
    }

    void (*orig_func)() = nullptr; // 设置orig_func，被hook的函数原始地址会放到这里来

    GumInterceptor *interceptor;
    interceptor = gum_interceptor_obtain(); // 获取全局的 Frida 的 hook 引擎本体
    LOGS("gum_interceptor_obtain => %p", interceptor);
    if (interceptor == nullptr) {
    }

    gum_interceptor_begin_transaction(interceptor); // 开启一次事务， Frida Gum 的 hook 修改需要放在 transaction 中，不然后中途失败会造成崩溃

    g_target_addr = target_addr;
    g_interceptor = interceptor;

    // Hook
    // Frida 会在 hook 时，把"原函数入口地址"写进 backup 指针里
    auto ret = gum_interceptor_replace(
        interceptor,
        target_addr,
        (void *) replace_func,
        interceptor,
        (void **) &orig_func
    );

    gum_interceptor_end_transaction(interceptor); // 结束事务，确保 hook 安全完成

    LOGS("flush");
    gum_interceptor_flush(interceptor); // 强制让 hook 生效， 没有flush之前可能是pending的状态
    if (ret == 0) {
    } else {
    }
}
}

extern "C" {
int hello() {
    return 1;
}
};
