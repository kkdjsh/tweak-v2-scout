// =============================================================================
// v3 - 抓网络请求 + 枚举 dyld image + hook UIAlertAction handler
// 目标: 拿到卡密验证接口的 URL/响应格式, 找到 mango.framework 路径
// =============================================================================

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

static NSString *v3LogPath(void) {
    NSString *doc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [doc stringByAppendingPathComponent:@"v3_log.txt"];
}
static void v3Log(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"%@", s);
    NSString *p = v3LogPath();
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) { [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; }
    else { [h seekToEndOfFile]; [h writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile]; }
}

#pragma mark - 枚举所有 dyld image, 找 mango / dylib / framework

static void DumpDyldImages(void) {
    uint32_t count = _dyld_image_count();
    v3Log(@"\n========== dyld images (共 %u 个) ==========", count);
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        NSString *p = [NSString stringWithUTF8String:path ?: ""];
        // 只打非系统的
        if ([p containsString:@"/var/"] || [p containsString:@"mango"] ||
            [p containsString:@"CardKey"] || [p containsString:@"License"] ||
            [p containsString:@"Auth"] || [p containsString:@"PlugIn"]) {
            v3Log(@"  [%u] %@", i, p);
        }
    }
    v3Log(@"========== dyld images end ==========\n");
}

#pragma mark - Hook NSURLSession dataTask, 抓网络请求

@interface NSURLSessionTaskHook : NSObject
@end

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    NSURL *url = request.URL;
    NSString *method = request.HTTPMethod ?: @"GET";
    NSString *body = [[NSString alloc] initWithData:request.HTTPBody ?: [NSData data] encoding:NSUTF8StringEncoding];
    v3Log(@"[v3网络] --> %@ %@", method, url.absoluteString);
    if (body.length) v3Log(@"[v3网络]     body=%@", body);
    for (NSString *k in request.allHTTPHeaderFields) {
        v3Log(@"[v3网络]     H[%@]=%@", k, request.allHTTPHeaderFields[k]);
    }
    void (^newHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
        NSString *respStr = [[NSString alloc] initWithData:data ?: [NSData data] encoding:NSUTF8StringEncoding];
        v3Log(@"[v3网络] <-- %ld %@", (long)r.statusCode, url.absoluteString);
        v3Log(@"[v3网络]     resp=%@", respStr);
        completionHandler(data, response, error);
    };
    return %orig(request, newHandler);
}

%end

#pragma mark - Hook UIAlertAction, 打印 handler

%hook UIAlertAction

- (void)setHandler:(void (^)(UIAlertAction *))handler {
    v3Log(@"[v3弹窗] UIAlertAction title=%@ style=%ld handler=%p", self.title, (long)self.style, handler);
    %orig(handler);
}

%end

#pragma mark - Hook UIAlertController, 打印更多信息

%hook UIAlertController

+ (instancetype)alertControllerWithTitle:(NSString *)title
                                 message:(NSString *)message
                          preferredStyle:(UIAlertControllerStyle)style {
    id alert = %orig(title, message, style);
    v3Log(@"[v3弹窗] === title=%@ message=%@ style=%lu ===", title, message, (unsigned long)style);
    return alert;
}

%end

#pragma mark - %ctor

%ctor {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            DumpDyldImages();
        });
    }
}
