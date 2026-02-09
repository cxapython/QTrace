//记得手机设置setenforce 0
function listLoadedModules() {
    console.log("--- 正在枚举已加载的模块(.so) ---");

    Process.enumerateModules().forEach(function (module) {
        if (module.name == "libQTrace.so") {
            // 打印模块名、基址、大小以及完整路径
            console.log("模块名: " + module.name);
            console.log("  基址: " + module.base);
            console.log("  大小: " + module.size + " bytes");
            console.log("  路径: " + module.path);
            console.log("-------------------------------------------");
            return
        }
    });
}
function main(){
    try {
        let so_path = "/data/local/tmp/libQTrace.so"
// 加载我们的so
        let dlopen = new NativeFunction(Module.findExportByName(null, "dlopen"), "pointer", ["pointer", "int"])
        let handle = dlopen(Memory.allocUtf8String(so_path), 2) // RTLD_NOW
        console.log("dlopen handle: " + handle)
        if (handle.isNull()) {
            console.error("dlopen failed")
            return
        }

        let m = Process.findModuleByName("libQTrace.so")
        if (!m) {
            console.error("load so fail")
            return
        }
        listLoadedModules()

        // /*——hello测试——*/
        // let f = m.findExportByName("hello")
        // if (!f) {
        //     console.error("load so fail, no sym")
        //     return
        // }
        // console.log("hello address: " + f)
        // let test_function = new NativeFunction(f, "int", [])
        // let res = test_function()
        // console.log(res)

        // 获取目标模块
        let mod = Process.findModuleByName("libnative-lib.so") // find target lib
        if (!mod) {
            console.error("libnative-lib.so not found")
            return
        }
        console.log("libnative-lib.so base: " + mod.base)
        const UUIDCheckSumOffset = 0xff30; // UUIDCheckSum function offset in libnative-lib.so
        let targetAddr = mod.base.add(UUIDCheckSumOffset)
        console.log("Target address: " + targetAddr)

// 调用gum_handle
        console.log("Calling gum_handle with target address...")
        let f = m.findExportByName("gum_handle")
        let test_function = new NativeFunction(f, "void", ["pointer"])
        test_function(targetAddr)
        console.log("gum_handle call completed (no exception)")
    }catch (e){
        console.error("exception in test():"+e);
    }

}