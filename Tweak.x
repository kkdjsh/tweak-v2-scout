// v12 - hook C 函数 memcmp/strcmp/strncmp
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <execinfo.h>
#import <substrate.h>

static NSString *v12LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v12_log.txt"];
}
static void v12Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v12LogPath();
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
                v12Log(@"[v12] mongo: %p - %p", (void*)slide, (void*)maxEnd);
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

// 原始函数
static int (*orig_memcmp)(const void *, const void *, size_t) = NULL;
static int (*orig_strcmp)(const char *, const char *) = NULL;
static int (*orig_strncmp)(const char *, const char *, size_t) = NULL;

// hook 实现
static int hook_memcmp(const void *a, const void *b, size_t n) {
    int o = orig_memcmp(a, b, n);
    if (CalledByMongo() && o != 0 && n >= 4 && n <= 128) {
        v12Log(@"[v12] memcmp n=%zu o=%d -> 0", n, o);
        return 0;
    }
    return o;
}
static int hook_strcmp(const char *a, const char *b) {
    int o = orig_strcmp(a, b);
    if (CalledByMongo() && o != 0) {
        v12Log(@"[v12] strcmp a=%s b=%s -> 0", a, b);
        return 0;
    }
    return o;
}
static int hook_strncmp(const char *a, const char *b, size_t n) {
    int o = orig_strncmp(a, b, n);
    if (CalledByMongo() && o != 0 && n >= 4 && n <= 128) {
        v12Log(@"[v12] strncmp n=%zu -> 0", n);
        return 0;
    }
    return o;
}

// 自动调确认 handler
%hook UIAlertController
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;
    v12Log(@"[v12] 弹窗出现");
    for (UITextField *f in self.textFields) f.text = @"AAAA-BBBB-CCCC-DDDD";
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            Ivar iv = class_getInstanceVariable([UIAlertAction class], "_handler");
            if (iv) {
                id handler = object_getIvar(a, iv);
                typedef void (^blk)(UIAlertAction *);
                blk h = (blk)handler;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    v12Log(@"[v12] >>> 调handler");
                    h(a);
                });
            }
        }
    }
}
%end

%ctor {
    FindMongo();
    MSHookFunction((void*)memcmp, (void*)hook_memcmp, (void**)&orig_memcmp);
    MSHookFunction((void*)strcmp, (void*)hook_strcmp, (void**)&orig_strcmp);
    MSHookFunction((void*)strncmp, (void*)hook_strncmp, (void**)&orig_strncmp);
    v12Log(@"[v12] memcmp/strcmp hooked");
}
