#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>

void taintOneLeg(BOOL cond) {
    char buf[256];
    if (cond) {
        fgets(buf, sizeof(buf), stdin);
    } else {
        snprintf(buf, sizeof(buf), "%s", "safe-static");
    }
    system(buf);
}

void taintOverwritten(BOOL cond) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    if (cond) {
        snprintf(buf, sizeof(buf), "%s", "clean-then");
    } else {
        snprintf(buf, sizeof(buf), "%s", "clean-else");
    }
    system(buf);
}
