// Cross-file argument flow audit fixture (Objective-C).
#import <Foundation/Foundation.h>
#import <stdio.h>

extern void runPipeline(const char *payload);

void handler(void) {
    // POSITIVE
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    runPipeline(buf);
}

void handlerSplit(void) {
    // POSITIVE
    char user[128];
    char flag[128];
    fgets(user, sizeof(user), stdin);
    fgets(flag, sizeof(flag), stdin);
    char joined[256];
    snprintf(joined, sizeof(joined), "%s:%s", user, flag);
    runPipeline(joined);
}
