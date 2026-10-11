// v6 - 侦察 handler 内部到底调了什么
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <execinfo.h>

static NSString *v6LogPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0] stringByAppendingPathComponent:@"v6_log.txt"];
}
static void v6Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v6LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else { [h seekToEndOfFile]; [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile]; }
}

// 维护所有 mongo.dylib 的地址范围
static NSMutableArray *g_mongoRanges = nil;
static void FindMongo(void) {
    if (!g_mongoRanges) g_mongoRanges = [NSMutableArray new];
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
            if (![g_mongoRanges containsObject:r]) {
                [g_mongoRanges addObject:r];
                v6Log(@"[v6] mongo range: %p - %p", (void*)slide, (void*)maxEnd);
            }
        }
    }
}

static BOOL CalledByMongo(void) {
    void *callers[12]; int n = backtrace(callers, 12);
    for (int i=0; i<n; i++) {
        uintptr_t pc = (uintptr_t)callers[i];
        for (NSArray *r in g_mongoRanges) {
            if (pc >= [r[0] unsignedLongValue] && pc < [r[1] unsignedLongValue]) return YES;
        }
    }
    return NO;
}

// hook NSData base64 decode
%hook NSData
- (id)initWithBase64EncodedString:(NSString *)s options:(NSDataBase64DecodingOptions)opts {
    id r = %orig(s, opts);
    if (CalledByMongo()) {
        v6Log(@"[v6] base64 decode: input=%@ -> outlen=%lu", s, (unsigned long)[(NSData*)r length]);
    }
    return r;
}
- (BOOL)isEqualToData:(NSData *)other {
    BOOL orig = %orig(other);
    if (CalledByMongo()) {
        v6Log(@"[v6] NSData==: self.len=%lu other.len=%lu orig=%d", (unsigned long)self.length, (unsigned long)other.length, orig);
    }
    return orig;
}
%end

// hook NSString
%hook NSString
- (BOOL)isEqualToString:(NSString *)aString {
    BOOL orig = %orig(aString);
    if (CalledByMongo()) {
        v6Log(@"[v6] NSString==: self=%@ arg=%@ orig=%d", self, aString, orig);
    }
    return orig;
}
- (NSData *)dataUsingEncoding:(NSStringEncoding)enc {
    NSData *r = %orig(enc);
    if (CalledByMongo()) {
        v6Log(@"[v6] str->data: self=%@ len=%lu", self, (unsigned long)r.length);
    }
    return r;
}
%end

// hook UIAlertController 自动调确认
%hook UIAlertController
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *title = self.title ?: @"";
    if (![title containsString:@"坦克秒"] && ![title containsString:@"授权"]) return;
    v6Log(@"[v6] 弹窗: %@", title);
    for (UITextField *f in self.textFields) {
        f.text = @"AAAA-BBBB-CCCC-DDDD";
    }
    for (UIAlertAction *a in self.actions) {
        if ([a.title isEqualToString:@"确认"]) {
            Ivar iv = class_getInstanceVariable([UIAlertAction class], "_handler");
            if (iv) {
                id handler = object_getIvar(a, iv);
                typedef void (^blk)(UIAlertAction *);
                blk h = (blk)handler;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    v6Log(@"[v6] === 调确认handler ===");
                    h(a);
                });
            }
        }
    }
}
%end

%ctor { FindMongo(); }
