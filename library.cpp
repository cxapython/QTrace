#include <android/log.h>
#include "include/frida-gum.h"
#include "include/QBDI.h"
#include "include/QBDI/State.h"
#include "include/QBDI/VM.h"
#include "include/QBDI/VM_C.h"
#include <cinttypes>
#define LOG_TAG "Qtrace"
#define LOGS(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##__VA_ARGS__);

// 定义postInstruction回调函数，用于打印反汇编指令
static int counter = 0; // 全局计数器，用于控制打印次数

QBDI::VMAction postInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    if (counter < 10) {
        // 获取当前指令的分析信息，包括反汇编
        const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION |
            QBDI::ANALYSIS_DISASSEMBLY |
            QBDI::ANALYSIS_OPERANDS
        );

        if (analysis != nullptr && analysis->disassembly != nullptr) {
            // 打印反汇编指令（人类可读）
            LOGS("Disassembly at 0x%" PRIx64 ": %s", analysis->address, analysis->disassembly);
        }
        counter++;
    }

    return QBDI::VMAction::CONTINUE; // 继续执行
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
        state->x29 = cpu->fp;
        state->nzcv = cpu->nzcv;
    } else {
        for (int i = 0; i < 29; i++) {
            cpu->x[i] = QBDI_GPR_GET(state, i);
        }

        cpu->fp = state->x29;
        cpu->lr = state->lr;
        cpu->sp = state->sp;
        cpu->nzcv = state->nzcv;
    }
}

QBDI::VM vm_init(void *address) {
    QBDI::VM qvm{}; // 实例化
    void *data = nullptr; // 不需要传递数据

    // 注册后指令回调，用于打印机器码
    qvm.addCodeCB(QBDI::POSTINST, postInstruction, data);

    // 插桩当前进程所有so ： 将所有可执行内存映射添加到 instrumented 范围集合中。
    qvm.instrumentAllExecutableMaps();

    return qvm;
}

QBDI::rword replace_func() {
    LOGS("replace called");

    auto context = (GumInvocationContext *) gum_interceptor_get_current_invocation();
    // 从 Frida 拿到当前函数调用信息（参数、寄存器、原函数地址等上下文）
    auto interceptor = (GumInterceptor *) gum_invocation_context_get_replacement_data(context); // 拿到 interceptor 本体

    gum_interceptor_revert(interceptor, context->function); // 暂时取消 Hook， 恢复函数
    gum_interceptor_flush(interceptor); // 立即执行 ：暂时取消 Hook， 恢复函数
    //初始化自定义 QBDI 虚拟机
    auto qvm = vm_init(context->function);

    // 同步 ：Frida 通用寄存器 -> qbdi 通用寄存器
    auto state = qvm.getGPRState();
    syn_reg_gum(context->cpu_context, state, true);

    // 执行 trace 时 QBDI 不允许使用真实栈（否则破坏程序），所以给 VM 创建一块 独立虚拟栈
    uint8_t *fakestack;
    QBDI::allocateVirtualStack(state, 0x10000, &fakestack);

    /*
     * 切换到 QBDI 私有栈   state
     * 跳到原函数入口      context->function
     * 完整执行函数
     * 把返回值拿出来      ret
     */
    QBDI::rword ret;
    qvm.switchStackAndCall(&ret, (QBDI::rword) context->function);

    // 同步 ：qbdi 通用寄存器 -> Frida 通用寄存器
    syn_reg_gum(context->cpu_context, state, false);

    LOGS("replace end");
    return ret;
}

extern "C" {
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
    }

    void (*orig_func)() = nullptr; // 设置orig_func，被hook的函数原始地址会放到这里来

    GumInterceptor *interceptor;
    interceptor = gum_interceptor_obtain(); // 获取全局的 Frida 的 hook 引擎本体
    LOGS("gum_interceptor_obtain => %p", interceptor);
    if (interceptor == nullptr) {
    }

    gum_interceptor_begin_transaction(interceptor); // 开启一次事务， Frida Gum 的 hook 修改需要放在 transaction 中，不然后中途失败会造成崩溃

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
