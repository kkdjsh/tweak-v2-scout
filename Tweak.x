// v11 - hook objc_msgSend, 看 handler 里调了什么
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <execinfo.h>
#import <substrate.h>

static NSString *v11LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v11_log.txt"];
}
static void v11Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v11LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else { [h seekToEndOfFile]; [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile]; }
}

static NSMutableArray *g_ranges = nil;
static void FindMongo(void) {
    if (!g_ranges) g_ranges = [NSMutableArray new];
    uint32_t n = _dyld_image_count();
    for (uint32_t i=0; i<n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, "mongo.dylib")) {
            const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
            uintptr_t slide = _dyld_get_image_vmaddr_slide(i);
            uintptr_t maxEnd = 0;
            struct load_command *lc = (struct load_command *)((uintptr_t)h + sizeof(struct mach_header_64));
            for (uint32_t j=0; j<h->ncmds; j++) {
                if (lc->cmd == LC_SEGMENT_64) {
                    struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                    maxEnd = MAX(maxEnd, slide + seg->vmaddr + seg->vmsize);
                }
                lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
            }
            NSArray *r = @[@(slide), @(maxEnd)];
            if (![g_ranges containsObject:r]) {
                [g_ranges addObject:r];
                v11Log(@"[v11] mongo: %p - %p", (void*)slide, (void*)maxEnd);
            }
        }
    }
}

static BOOL CalledByMongo(void) {
    void *callers[15]; int n = backtrace(callers, 15);
    for (int i=0; i<n; i++) {
        uintptr_t pc = (uintptr_t)callers[i];
        for (NSArray *r in g_ranges) {
            if (pc >= [r[0] unsignedLongValue] && pc < [r[1] unsignedLongValue]) return YES;
        }
    }
    return NO;
}

// 原始 objc_msgSend
static id (*orig_objc_msgSend)(id, SEL, ...) = NULL;

// 替换的 objc_msgSend
static id hook_objc_msgSend(id self, SEL _cmd, ...) {
    if (CalledByMongo()) {
        const char *sel = sel_getName(_cmd);
        v11Log(@"[v11] msgSend: [%@ %s]", NSStringFromClass([self class]), sel);
    }
    va_list ap; va_start(ap, _cmd);
    id ret = orig_objc_msgSend(self, _cmd, ap);
    va_end(ap);
    return ret;
}

// 自动调确认 handler
%hook UIAlertController
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;
    v11Log(@"[v11] 弹窗出现: %@", title);
    for (UITextField *f in self.textFields) f.text = @"AAAA-BBBB-CCCC-DDDD";
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            Ivar iv = class_getInstanceVariable([UIAlertAction class], "_handler");
            if (iv) {
                id handler = object_getIvar(a, iv);
                typedef void (^blk)(UIAlertAction *);
                blk h = (blk)handler;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    v11Log(@"[v11] >>> 调handler");
                    h(a);
                });
            }
        }
    }
}
%end

%ctor {
    FindMongo();
    MSHookFunction((void*)objc_msgSend, (void*)hook_objc_msgSend, (void**)&orig_objc_msgSend);
    v11Log(@"[v11] objc_msgSend hooked");
}
