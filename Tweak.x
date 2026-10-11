// =============================================================================
// v2.1 - 侦察版: 文件日志版
// 日志同时打到 syslog 和 Documents/v2scout_log.txt
// 不越狱用户用爱思助手/iTools 打开 App 沙盒 Documents 就能拿到
// =============================================================================

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *const kHookSelName = @"FkvoMtqhqsFMqgIn:FkvoMtghqsFMqgIn:";

static NSString *v2LogPath(void) {
    NSString *doc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [doc stringByAppendingPathComponent:@"v2scout_log.txt"];
}

static void v2Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v2LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else {
        [h seekToEndOfFile];
        [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
        [h closeFile];
    }
}

#pragma mark - 枚举插件相关类

static void DumpPluginClasses(void) {
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    NSSet *kw = [NSSet setWithObjects:
                 @"mango", @"Mango", @"MANGO",
                 @"Auth", @"auth", @"License", @"license",
                 @"Card", @"card", @"CardKey", @"cardkey",
                 @"Key", @"Vip", @"VIP", @"Expire", @"expire",
                 @"克秒", @"授权", @"验证", nil];
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"\n========== 插件相关类扫描 ==========\n"];
    for (unsigned int i = 0; i < classCount; i++) {
        Class c = classes[i];
        const char *name = class_getName(c);
        NSString *clsName = [NSString stringWithUTF8String:name ?: ""];
        BOOL hit = NO;
        for (NSString *k in kw) { if ([clsName containsString:k]) { hit = YES; break; } }
        if (!hit) continue;
        [report appendFormat:@"\n● Class: %@\n", clsName];
        unsigned int mCount = 0;
        Method *methods = class_copyMethodList(c, &mCount);
        for (unsigned int j = 0; j < mCount; j++) {
            SEL sel = method_getName(methods[j]);
            [report appendFormat:@"    -[%@ %@]\n", clsName,
             [NSString stringWithUTF8String:sel_getName(sel) ?: ""]];
        }
        free(methods);
        Class meta = object_getClass(c);
        if (meta && meta != c) {
            unsigned int mcCount = 0;
            Method *cmethods = class_copyMethodList(meta, &mcCount);
            for (unsigned int j = 0; j < mcCount; j++) {
                SEL sel = method_getName(cmethods[j]);
                [report appendFormat:@"    +[%@ %@]\n", clsName,
                 [NSString stringWithUTF8String:sel_getName(sel) ?: ""]];
            }
            free(cmethods);
        }
    }
    free(classes);
    v2Log(@"%@", report);
    v2Log(@"[v2侦察] 日志文件路径: %@", v2LogPath());
}

#pragma mark - Hook UIAlertController

%hook UIAlertController

+ (instancetype)alertControllerWithTitle:(NSString *)title
                                 message:(NSString *)message
                          preferredStyle:(UIAlertControllerStyle)style {
    id alert = %orig(title, message, style);
    BOOL isAuth = NO;
    if ([title containsString:@"授权"] || [title containsString:@"克秒"] ||
        [message containsString:@"授权"] || [message containsString:@"授权码"] ||
        [message containsString:@"过期"] || [message containsString:@"到期"]) {
        isAuth = YES;
    }
    if (!isAuth) return alert;

    v2Log(@"[v2侦察] === 命中授权弹窗 ===");
    v2Log(@"[v2侦察] title    = %@", title);
    v2Log(@"[v2侦察] message  = %@", message);
    v2Log(@"[v2侦察] style    = %lu", (unsigned long)style);

    [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        v2Log(@"[v2侦察] textField placeholder = %@", textField.placeholder);
        textField.text = @"TEST-123456";
    }];
    return alert;
}

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    NSString *msg   = self.message ?: @"";
    if (![title containsString:@"授权"] && ![msg containsString:@"授权"] &&
        ![title containsString:@"克秒"] && ![msg containsString:@"授权码"]) return;
    v2Log(@"[v2侦察] --- 授权弹窗已出现, actions: ---");
    for (UIAlertAction *a in self.actions) {
        v2Log(@"[v2侦察]   action title=%@ style=%ld", a.title, (long)a.style);
    }
    for (UITextField *f in self.textFields) {
        v2Log(@"[v2侦察]   textField.text=%@ placeholder=%@", f.text, f.placeholder);
    }
}

%end

#pragma mark - %ctor

%ctor {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            Class cls = objc_getClass("NSData");
            if (cls) {
                SEL a = @selector(initWithBase64EncodedString:options:);
                SEL b = NSSelectorFromString(kHookSelName);
                Method ma = class_getInstanceMethod(cls, a);
                Method mb = class_getInstanceMethod(cls, b);
                if (ma && mb) {
                    method_exchangeImplementations(ma, mb);
                    v2Log(@"[v2] 已还原 NSData base64 原生实现");
                } else {
                    v2Log(@"[v2] base64 swizzle 未命中");
                }
            }
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            DumpPluginClasses();
        });
    }
}
