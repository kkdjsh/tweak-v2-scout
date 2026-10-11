// v7 - 全量侦察版: hook 所有可能的验证方法, 一次拿到全部信息
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <execinfo.h>

static NSString *v7LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v7_log.txt"];
}
static void v7Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v7LogPath();
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
                v7Log(@"[v7] mongo: %p - %p", (void*)slide, (void*)maxEnd);
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

#pragma mark - NSString 全家桶
%hook NSString
- (BOOL)isEqualToString:(NSString *)aString {
    BOOL o = %orig(aString);
    if (CalledByMongo()) v7Log(@"[v7] str== self=%@ arg=%@ o=%d", self, aString, o);
    return o;
}
- (NSUInteger)length {
    NSUInteger l = %orig;
    if (CalledByMongo() && l>=4 && l<=200) v7Log(@"[v7] str.len=%@ len=%lu", self, (unsigned long)l);
    return l;
}
- (const char *)UTF8String {
    const char *c = %orig;
    if (CalledByMongo() && c && strlen(c)>=4 && strlen(c)<=200) v7Log(@"[v7] str.utf8=%s", c);
    return c;
}
- (unichar)characterAtIndex:(NSUInteger)i {
    return %orig(i);
}
- (NSData *)dataUsingEncoding:(NSStringEncoding)enc {
    NSData *d = %orig(enc);
    if (CalledByMongo()) v7Log(@"[v7] str->data %@ len=%lu", self, (unsigned long)d.length);
    return d;
}
- (NSData *)dataUsingEncoding:(NSStringEncoding)enc allowLossyConversion:(BOOL)lossy {
    NSData *d = %orig(enc, lossy);
    if (CalledByMongo()) v7Log(@"[v7] str->data2 %@ len=%lu", self, (unsigned long)d.length);
    return d;
}
%end

#pragma mark - NSData 全家桶
%hook NSData
- (BOOL)isEqualToData:(NSData *)o {
    BOOL r = %orig(o);
    if (CalledByMongo()) v7Log(@"[v7] data== self=%lu other=%lu r=%d", (unsigned long)self.length, (unsigned long)o.length, r);
    return r;
}
- (NSUInteger)length {
    NSUInteger l = %orig;
    if (CalledByMongo() && l>=4 && l<=200) v7Log(@"[v7] data.len=%lu", (unsigned long)l);
    return l;
}
- (const void *)bytes {
    const void *b = %orig;
    if (CalledByMongo() && self.length>=4 && self.length<=200) {
        NSData *d = [NSData dataWithBytes:b length:MIN(self.length, 64)];
        v7Log(@"[v7] data.bytes=%@", [d base64EncodedStringWithOptions:0]);
    }
    return b;
}
- (id)initWithBase64EncodedString:(NSString *)s options:(NSDataBase64DecodingOptions)o {
    id r = %orig(s, o);
    if (CalledByMongo()) v7Log(@"[v7] b64dec input=%@ outlen=%lu", s, (unsigned long)[(NSData*)r length]);
    return r;
}
%end

#pragma mark - UITextField
%hook UITextField
- (NSString *)text {
    NSString *t = %orig;
    if (CalledByMongo()) v7Log(@"[v7] tf.text read: %@", t);
    return t;
}
%end

#pragma mark - NSNumber
%hook NSNumber
- (BOOL)boolValue {
    BOOL b = %orig;
    if (CalledByMongo()) v7Log(@"[v7] num.bool=%@ -> %d", self, b);
    return b;
}
- (NSInteger)integerValue {
    NSInteger i = %orig;
    if (CalledByMongo()) v7Log(@"[v7] num.int=%@ -> %ld", self, (long)i);
    return i;
}
%end

#pragma mark - NSDictionary
%hook NSDictionary
- (id)objectForKey:(id)k {
    id v = %orig(k);
    if (CalledByMongo() && [k isKindOfClass:[NSString class]]) {
        NSString *ks = (NSString *)k;
        if (ks.length>=3 && ks.length<=50) v7Log(@"[v7] dict[%@] = %@", ks, v);
    }
    return v;
}
%end

#pragma mark - NSUserDefaults
%hook NSUserDefaults
- (id)objectForKey:(NSString *)k {
    id v = %orig(k);
    if (CalledByMongo()) v7Log(@"[v7] defaults[%@] = %@", k, v);
    return v;
}
- (BOOL)boolForKey:(NSString *)k {
    BOOL v = %orig(k);
    if (CalledByMongo()) v7Log(@"[v7] defaults.bool[%@] = %d", k, v);
    return v;
}
%end

#pragma mark - UIAlertController 自动调确认
%hook UIAlertController
+ (instancetype)alertControllerWithTitle:(NSString *)title message:(NSString *)msg preferredStyle:(NSInteger)s {
    id r = %orig(title, msg, s);
    v7Log(@"[v7] === 弹窗创建: title=%@ msg=%@ ===", title, msg);
    return r;
}
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;
    v7Log(@"[v7] 弹窗出现: %@", title);
    for (UITextField *f in self.textFields) f.text = @"AAAA-BBBB-CCCC-DDDD";
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            Ivar iv = class_getInstanceVariable([UIAlertAction class], "_handler");
            if (iv) {
                id handler = object_getIvar(a, iv);
                typedef void (^blk)(UIAlertAction *);
                blk h = (blk)handler;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    v7Log(@"[v7] >>> 调确认handler");
                    h(a);
                });
            }
        }
    }
}
%end

#pragma mark - UIAlertAction
%hook UIAlertAction
- (void)setHandler:(void (^)(UIAlertAction *))h {
    v7Log(@"[v7] action.title=%@ style=%ld handler=%p", self.title, (long)self.style, h);
    %orig(h);
}
%end

%ctor { FindMongo(); }
