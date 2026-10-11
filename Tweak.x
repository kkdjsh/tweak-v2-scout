// v9 - 直接 patch mongo.dylib 验证函数
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <sys/mman.h>

static NSString *v9LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v9_log.txt"];
}
static void v9Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v9LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else { [h seekToEndOfFile]; [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile]; }
}

static uintptr_t g_base = 0;

static void FindAndPatch(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i=0; i<n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, "mongo.dylib")) {
            const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
            uintptr_t slide = _dyld_get_image_vmaddr_slide(i);
            v9Log(@"[v9] mongo base: %p slide: %p", h, (void*)slide);
            g_base = slide;

            // 反汇编里 0x7C1C 调了 0x7D14, cmp w0,#0 判断验证
            // patch 0x7D14 为: mov w0, #1; ret
            uintptr_t patchAddr = slide + 0x7D14;
            v9Log(@"[v9] patch target: %p", (void*)patchAddr);

            // 先读原来的指令
            uint32_t *orig = (uint32_t *)patchAddr;
            v9Log(@"[v9] orig insn: 0x%x 0x%x", orig[0], orig[1]);

            // 修改内存保护为可写
            kern_return_t kr = vm_protect(mach_task_self(),
                (vm_address_t)patchAddr, 16, FALSE,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            v9Log(@"[v9] vm_protect ret: %d", kr);

            // 写入: mov w0, #1; ret
            // mov w0, #1 = 0x52800020
            // ret = 0xd65f03c0
            uint32_t patch[2] = {0x52800020, 0xd65f03c0};
            memcpy((void*)patchAddr, patch, 8);

            // 恢复保护
            vm_protect(mach_task_self(),
                (vm_address_t)patchAddr, 16, FALSE,
                VM_PROT_READ | VM_PROT_EXECUTE);

            v9Log(@"[v9] patched! new insn: 0x%x 0x%x", ((uint32_t*)patchAddr)[0], ((uint32_t*)patchAddr)[1]);
            break;
        }
    }
}

%ctor { FindAndPatch(); }
