#import <Foundation/Foundation.h>
#import <stdlib.h>

void runInOtherFile(NSString *cmd) {
    // POSITIVE (cross-file)
    system([cmd UTF8String]);
}
