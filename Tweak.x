// v5 - 真绕过: 自动调确认handler + 拦截NSData比对 + 不再dismiss
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <execinfo.h>

static NSString *v5LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v5_log.txt"];
}
static void v5Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v5LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else { [h seekToEndOfFile]; [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile]; }
}

static uintptr_t g_mongoStart = 0, g_mongoEnd = 0;
static void FindMongo(void) {
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
            g_mongoStart = slide; g_mongoEnd = maxEnd;
            v5Log(@"[v5] mongo: %p - %p", (void*)g_mongoStart, (void*)g_mongoEnd);
            return;
        }
    }
}

static BOOL CalledByMongo(void) {
    void *callers[12]; int n = backtrace(callers, 12);
    for (int i=0; i<n; i++) {
        uintptr_t pc = (uintptr_t)callers[i];
        if (pc >= g_mongoStart && pc < g_mongoEnd) return YES;
    }
    return NO;
}

// hook NSData isEqualToData:
%hook NSData
- (BOOL)isEqualToData:(NSData *)other {
    BOOL orig = %orig(other);
    if (CalledByMongo() && !orig) {
        v5Log(@"[v5] NSData比对拦截 len=%lu -> YES", (unsigned long)self.length);
        return YES;
    }
    return orig;
}
%end

// hook NSString isEqualToString: (兜底)
%hook NSString
- (BOOL)isEqualToString:(NSString *)aString {
    BOOL orig = %orig(aString);
    if (CalledByMongo() && !orig) {
        v5Log(@"[v5] NSString比对拦截 self=%@ arg=%@ -> YES", self, aString);
        return YES;
    }
    return orig;
}
%end

// hook UIAlertController, 自动调确认handler
%hook UIAlertController
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;
    v5Log(@"[v5] 命中弹窗: %@, 准备自动调确认handler", title);

    // 填码
    for (UITextField *f in self.textFields) {
        f.text = @"AAAA-BBBB-CCCC-DDDD";
        v5Log(@"[v5] 填入: %@", f.text);
    }

    // 找确认按钮, 拿 _handler, 直接调用
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            // 通过 runtime 拿 _handler
            Ivar iv = class_getInstanceVariable([UIAlertAction class], "_handler");
            if (iv) {
                id handler = object_getIvar(a, iv);
                v5Log(@"[v5] 确认 handler=%@, 直接调用", handler);
                typedef void (^blk)(UIAlertAction *);
                blk h = (blk)handler;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    v5Log(@"[v5] 调用确认 handler");
                    h(a);
                });
            } else {
                v5Log(@"[v5] 找不到 _handler ivar");
            }
        }
    }
}
%end

%ctor { FindMongo(); }
