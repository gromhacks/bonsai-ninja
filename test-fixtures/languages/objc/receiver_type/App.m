// Receiver-type audit fixture (Objective-C).
// system() is libc free function.
#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>

void handle(void) {
    // POSITIVE
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    system(buf);
}
