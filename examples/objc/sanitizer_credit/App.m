#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>

void unsanitized(void) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    system(buf);
}

void sanitized(void) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    NSString *raw = [NSString stringWithUTF8String:buf];
    NSString *safe = [raw stringByReplacingOccurrencesOfString:@"[^A-Za-z0-9_-]"
                                                    withString:@""
                                                       options:NSRegularExpressionSearch
                                                         range:NSMakeRange(0, [raw length])];
    system([safe UTF8String]);
}
