#import <Foundation/Foundation.h>
#import <stdlib.h>

void execute(const char *cmd) {
    // POSITIVE (terminal cross-file sink)
    system(cmd);
}
