// v8 - 暴力绕过: 不创建授权弹窗 + 所有比对返回YES
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <execinfo.h>

static NSString *v8LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v8_log.txt"];
}
static void v8Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v8LogPath();
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
                v8Log(@"[v8] mongo: %p - %p", (void*)slide, (void*)maxEnd);
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

// 核心: 不创建授权弹窗
%hook UIAlertController
+ (instancetype)alertControllerWithTitle:(NSString *)title message:(NSString *)msg preferredStyle:(NSInteger)s {
    if ([title containsString:@"坦克秒"] || [title containsString:@"授权"] || [msg containsString:@"授权码"]) {
        v8Log(@"[v8] *** 拦截授权弹窗: title=%@ msg=%@ ***", title, msg);
        // 返回一个空的弹窗, 但不显示
        id r = %orig(title, msg, s);
        return r;
    }
    return %orig(title, msg, s);
}
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;
    v8Log(@"[v8] 授权弹窗出现, 自动填码+调handler");
    for (UITextField *f in self.textFields) f.text = @"AAAA-BBBB-CCCC-DDDD";
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            Ivar iv = class_getInstanceVariable([UIAlertAction class], "_handler");
            if (iv) {
                id handler = object_getIvar(a, iv);
                typedef void (^blk)(UIAlertAction *);
                blk h = (blk)handler;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    v8Log(@"[v8] 调handler");
                    h(a);
                });
            }
        }
    }
}
%end

// 暴力: NSString 长度在 8-64 且调用者在 mongo 内就返回 YES
%hook NSString
- (BOOL)isEqualToString:(NSString *)aString {
    BOOL o = %orig(aString);
    if (CalledByMongo() && !o && self.length >= 4 && self.length <= 200) {
        v8Log(@"[v8] str== self=%@ arg=%@ o=%d -> YES", self, aString, o);
        return YES;
    }
    return o;
}
%end

// 暴力: NSData 长度在 8-64 且调用者在 mongo 内就返回 YES
%hook NSData
- (BOOL)isEqualToData:(NSData *)o {
    BOOL r = %orig(o);
    if (CalledByMongo() && !r && self.length >= 4 && self.length <= 200) {
        v8Log(@"[v8] data== self=%lu other=%lu r=%d -> YES", (unsigned long)self.length, (unsigned long)o.length, r);
        return YES;
    }
    return r;
}
%end

// 暴力: NSObject isEqual: 且调用者在 mongo 内就返回 YES
%hook NSObject
- (BOOL)isEqual:(id)object {
    BOOL o = %orig(object);
    if (CalledByMongo() && !o && [self isKindOfClass:[NSString class]]) {
        v8Log(@"[v8] isEqual: self=%@ obj=%@ o=%d -> YES", self, object, o);
        return YES;
    }
    return o;
}
%end

%ctor { FindMongo(); }
