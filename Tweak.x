// =============================================================================
// v2 - 侦察版: 拦截授权码弹窗 + 撤销 base64 swizzle + 枚举插件类方法
// 目标: 拿到 mango 插件的类结构和验证方法名, 为 v3 精准绕过做准备
// =============================================================================

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *const kHookSelName = @"FkvoMtqhqsFMqgIn:FkvoMtghqsFMqgIn:";

#pragma mark - 工具: 枚举所有已加载类, 打印名字含关键词的类和方法

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
        for (NSString *k in kw) {
            if ([clsName containsString:k]) { hit = YES; break; }
        }
        if (!hit) continue;
        [report appendFormat:@"\n● Class: %@\n", clsName];
        // 实例方法
        unsigned int mCount = 0;
        Method *methods = class_copyMethodList(c, &mCount);
        for (unsigned int j = 0; j < mCount; j++) {
            SEL sel = method_getName(methods[j]);
            [report appendFormat:@"    -[%@ %@]\n", clsName,
             [NSString stringWithUTF8String:sel_getName(sel) ?: ""]];
        }
        free(methods);
        // 类方法
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
    NSLog(@"%@", report);
}

#pragma mark - Hook UIAlertController, 抓授权弹窗

%hook UIAlertController

+ (instancetype)alertControllerWithTitle:(NSString *)title
                                 message:(NSString *)message
                          preferredStyle:(UIAlertControllerStyle)style {
    id alert = %orig(title, message, style);

    // 判断是不是授权码弹窗
    BOOL isAuth = NO;
    if ([title containsString:@"授权"] || [title containsString:@"克秒"] ||
        [message containsString:@"授权"] || [message containsString:@"授权码"] ||
        [message containsString:@"过期"] || [message containsString:@"到期"]) {
        isAuth = YES;
    }
    if (!isAuth) {
        // textField 的 placeholder 要等 addTextField 才知道, 这里先放过
        return alert;
    }

    NSLog(@"[v2侦察] === 命中授权弹窗 ===");
    NSLog(@"[v2侦察] title    = %@", title);
    NSLog(@"[v2侦察] message  = %@", message);
    NSLog(@"[v2侦察] style    = %lu", (unsigned long)style);

    // 等 textField 加进来后, 监听它
    [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        NSLog(@"[v2侦察] textField placeholder = %@", textField.placeholder);
        NSLog(@"[v2侦察] textField 默认键盘   = %lu", (unsigned long)textField.keyboardType);
        // 自动填一个测试码
        textField.text = @"TEST-123456";
    }];

    // 把取消/确认按钮信息打出来
    // 注意: 这里 alert 是我们刚 %orig 出来的, 调用方后面还会 addAction,
    //       所以 action 列表要在 viewDidAppear 里再打一次.
    return alert;
}

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    // 如果是授权弹窗, 打印 actions 并尝试自动点确认
    NSString *title = self.title ?: @"";
    NSString *msg   = self.message ?: @"";
    if (![title containsString:@"授权"] && ![msg containsString:@"授权"] &&
        ![title containsString:@"克秒"] && ![msg containsString:@"授权码"]) {
        return;
    }
    NSLog(@"[v2侦察] --- 授权弹窗已出现, actions: ---");
    for (UIAlertAction *a in self.actions) {
        NSLog(@"[v2侦察]   action title=%@ style=%ld", a.title, (long)a.style);
    }
    for (UITextField *f in self.textFields) {
        NSLog(@"[v2侦察]   textField.text=%@ placeholder=%@", f.text, f.placeholder);
    }
}

%end

#pragma mark - %ctor: 撤销 dylib 的 base64 swizzle + 延迟扫描类

%ctor {
    @autoreleasepool {
        // 1) 撤销样本 dylib 的 base64 method swizzle (v1 逻辑)
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
                    NSLog(@"[v2] 已还原 NSData base64 原生实现");
                } else {
                    NSLog(@"[v2] base64 swizzle 未命中 (mOrig=%p mHook=%p)", ma, mb);
                }
            }
        });

        // 2) 延迟 2 秒, 等所有插件 framework 加载完, 扫描类
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            DumpPluginClasses();
        });
    }
}
