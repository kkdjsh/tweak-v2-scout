// v4 暴力绕过
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <execinfo.h>

static NSString *v4LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v4_log.txt"];
}
static void v4Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v4LogPath();
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
            g_mongoStart = (uintptr_t)h;  // 粗略范围, 用整个 image 页
            uintptr_t maxEnd = 0;
            struct load_command *lc = (struct load_command *)((uintptr_t)h + sizeof(struct mach_header_64));
            for (uint32_t j=0; j<h->ncmds; j++) {
                if (lc->cmd == LC_SEGMENT_64) {
                    struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                    maxEnd = MAX(maxEnd, slide + seg->vmaddr + seg->vmsize);
                }
                lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
            }
            g_mongoEnd = maxEnd;
            v4Log(@"[v4] mongo range: %p - %p", (void*)g_mongoStart, (void*)g_mongoEnd);
            return;
        }
    }
    v4Log(@"[v4] mongo.dylib not found");
}

%hook NSString
- (BOOL)isEqualToString:(NSString *)aString {
    BOOL orig = %orig(aString);
    void *callers[10]; int n = backtrace(callers, 10);
    BOOL fromMongo = NO;
    for (int i=0; i<n; i++) {
        uintptr_t pc = (uintptr_t)callers[i];
        if (pc >= g_mongoStart && pc < g_mongoEnd) { fromMongo = YES; break; }
    }
    if (fromMongo && !orig) {
        v4Log(@"[v4] 比对拦截 self=%@ arg=%@ -> YES", self, aString);
        return YES;
    }
    return orig;
}
%end

%hook UIAlertController
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;
    v4Log(@"[v4] 弹窗: %@, 自动填码并点确认", title);
    for (UITextField *f in self.textFields) f.text = @"AAAA-BBBB-CCCC-DDDD";
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                v4Log(@"[v4] 自动 dismiss 弹窗");
                [self dismissViewControllerAnimated:YES completion:nil];
            });
        }
    }
}
%end

%hook NSUserDefaults
- (id)objectForKey:(NSString *)k {
    id v = %orig(k);
    NSString *kl = [k lowercaseString];
    if ([kl containsString:@"auth"] || [kl containsString:@"license"] || [kl containsString:@"vip"] ||
        [kl containsString:@"expire"] || [kl containsString:@"card"] || [kl containsString:@"valid"]) {
        v4Log(@"[v4] defaults key=%@ -> 1", k);
        return @"1";
    }
    return v;
}
- (BOOL)boolForKey:(NSString *)k {
    BOOL v = %orig(k);
    NSString *kl = [k lowercaseString];
    if ([kl containsString:@"auth"] || [kl containsString:@"license"] || [kl containsString:@"vip"] ||
        [kl containsString:@"valid"]) { v4Log(@"[v4] bool key=%@ -> YES", k); return YES; }
    return v;
}
%end

%ctor { FindMongo(); }
