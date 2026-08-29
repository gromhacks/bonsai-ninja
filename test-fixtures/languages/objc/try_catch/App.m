#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>

void taintedThroughTry(void) {
    char buf[256];
    @try {
        fgets(buf, sizeof(buf), stdin);
    } @catch (NSException *ex) {
        buf[0] = 0;
    }
    system(buf);
}
