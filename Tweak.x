// =============================================================================
// v4 - 暴力绕过版: 卡密比对永远YES + 自动点确认 + NSUserDefaults验证标志
// 目标: 不管理验是什么, 让本地比对永远成功, 弹窗自动消失
// =============================================================================

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>

static NSString *v4LogPath(void) {
    NSString *doc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [doc stringByAppendingPathComponent:@"v4_log.txt"];
}
static void v4Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v4LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else { [h seekToEndOfFile]; [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile]; }
}

#pragma mark - 找 mongo.dylib 加载基址范围

static uintptr_t g_mongoBase = 0, g_mongoSize = 0;
static void FindMongo(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i=0; i<n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, "mongo.dylib")) {
            g_mongoBase = _dyld_get_image_vmaddr_slide(i) + _dyld_get_image_header(i)->__text.__paddr;
            struct load_command *lc = (struct load_command *)((uintptr_t)_dyld_get_image_header(i) + sizeof(struct mach_header_64));
            for (uint32_t j=0; j<((struct mach_header_64*)_dyld_get_image_header(i))->ncmds; j++) {
                if (lc->cmd == LC_SEGMENT_64) {
                    struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                    g_mongoSize = MAX(g_mongoSize, seg->vmaddr + seg->vmsize);
                }
                lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
            }
            v4Log(@"[v4] mongo.dylib base=%p size=%p", (void*)g_mongoBase, (void*)g_mongoSize);
            return;
        }
    }
    v4Log(@"[v4] mongo.dylib not found!");
}

#pragma mark - Hook NSString isEqualToString: 让 mongo.dylib 的比对永远 YES

%hook NSString

- (BOOL)isEqualToString:(NSString *)aString {
    BOOL orig = %orig(aString);
    // 只在调用栈来自 mongo.dylib 时强制 YES
    void *callers[8];
    int n = backtrace(callers, 8);
    BOOL fromMongo = NO;
    for (int i=0; i<n; i++) {
        uintptr_t pc = (uintptr_t)callers[i];
        if (pc >= g_mongoBase && pc < g_mongoSize) { fromMongo = YES; break; }
    }
    if (fromMongo && !orig) {
        v4Log(@"[v4] 拦截比对: self=%@ aString=%@ -> 返回YES", self, aString);
        return YES;
    }
    return orig;
}

%end

#pragma mark - Hook UIAlertController, 自动点确认

%hook UIAlertController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;

    v4Log(@"[v4] 命中授权弹窗: %@, 准备自动点确认", title);
    // 填一个测试码
    for (UITextField *f in self.textFields) {
        f.text = @"AAAA-BBBB-CCCC-DDDD";
    }
    // 找确认按钮
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                v4Log(@"[v4] 自动点击确认");
                // 直接调 action 的 handler
                // UIAlertAction 没有公开方法触发 handler, 用 performSelector 不行
                // 改成直接 dismiss, 然后 hook isEqualToString 让它通过
                [self dismissViewControllerAnimated:YES completion:nil];
            });
            break;
        }
    }
}

%end

#pragma mark - Hook NSUserDefaults, 验证标志永远成功

%hook NSUserDefaults

- (id)objectForKey:(NSString *)defaultName {
    id v = %orig(defaultName);
    NSString *k = [defaultName lowercaseString];
    if ([k containsString:@"auth"] || [k containsString:@"license"] ||
        [k containsString:@"vip"] || [k containsString:@"expire"] ||
        [k containsString:@"cardkey"] || [k containsString:@"verify"] ||
        [k containsString:@"valid"]) {
        v4Log(@"[v4] NSUserDefaults key=%@ orig=%@ -> 返回成功值", defaultName, v);
        return @"1";
    }
    return v;
}

- (BOOL)boolForKey:(NSString *)defaultName {
    BOOL v = %orig(defaultName);
    NSString *k = [defaultName lowercaseString];
    if ([k containsString:@"auth"] || [k containsString:@"license"] ||
        [k containsString:@"vip"] || [k containsString:@"verify"] ||
        [k containsString:@"valid"]) {
        v4Log(@"[v4] NSUserDefaults bool key=%@ orig=%d -> YES", defaultName, v);
        return YES;
    }
    return v;
}

%end

#pragma mark - %ctor

%ctor {
    @autoreleasepool {
        FindMongo();
    }
}
