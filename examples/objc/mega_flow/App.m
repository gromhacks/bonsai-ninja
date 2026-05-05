// mega_flow Objective-C entry — reads one tainted stdin line with
// fgets, then dispatches through a pipeline that exercises every
// idiomatic Obj-C flow construct (classes + categories, blocks,
// @try/@catch/@finally, dictionary literals, NSArray enumerations,
// properties, protocols).
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>

extern NSDictionary *orchestrate(NSDictionary *envelope);

void handle_request(void) {
    char buf[256] = {0};
    // SOURCE — fgets reads one tainted line from stdin.
    if (fgets(buf, sizeof(buf), stdin) != NULL) {
        buf[strcspn(buf, "\n")] = 0;
        NSString *raw = @(buf);
        NSString *user = [[NSProcessInfo processInfo].environment[@"USER"] ?: @"anon" copy];

        // Dictionary literal carrying the tainted cmd.
        NSDictionary *envelope = @{
            @"kind":   @"run",
            @"cmd":    raw,
            @"user":   user,
            @"length": @([raw length]),
            @"extras": @[raw],
        };

        orchestrate(envelope);
    }
}

int main(int argc, const char *argv[]) {
    (void)argc; (void)argv;
    @autoreleasepool {
        handle_request();
    }
    return 0;
}
