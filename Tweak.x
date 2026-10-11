// v10 - patch 0x7C20: cmp w0,#0 -> mov w0,#1
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>

static NSString *v10LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v10_log.txt"];
}
static void v10Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v10LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else { [h seekToEndOfFile]; [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile]; }
}

static void FindAndPatch(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i=0; i<n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, "mongo.dylib")) {
            uintptr_t slide = _dyld_get_image_vmaddr_slide(i);
            v10Log(@"[v10] mongo slide: %p", (void*)slide);

            // 0x7C20: cmp w0, #0  ->  mov w0, #1
            uintptr_t patchAddr = slide + 0x7C20;
            uint32_t *orig = (uint32_t *)patchAddr;
            v10Log(@"[v10] 0x7C20 orig: 0x%x", orig[0]);

            kern_return_t kr = vm_protect(mach_task_self(),
                (vm_address_t)patchAddr, 16, FALSE,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            v10Log(@"[v10] vm_protect: %d", kr);

            // mov w0, #1 = 0x52800020
            uint32_t patch = 0x52800020;
            memcpy((void*)patchAddr, &patch, 4);

            vm_protect(mach_task_self(),
                (vm_address_t)patchAddr, 16, FALSE,
                VM_PROT_READ | VM_PROT_EXECUTE);

            v10Log(@"[v10] patched! new: 0x%x", ((uint32_t*)patchAddr)[0]);
            break;
        }
    }
}

%ctor { FindAndPatch(); }
