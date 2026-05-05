#import <Foundation/Foundation.h>
#include <stdlib.h>

NSString *executeCmd(NSString *cmd) {
    // SINK — system() on cstring · objc.cmdi.system · CWE-78
    system([cmd UTF8String]);
    return cmd;
}

NSString *cleanTwin(void) {
    // NEGATIVE — same sink kind with a constant argument must not report.
    system("echo clean");
    return @"clean";
}
