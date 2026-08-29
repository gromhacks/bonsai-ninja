#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>

static const char *CONST_OK = "ls /tmp";

void decoy(void) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    (void)buf;
    system(CONST_OK);
}

NSString *unrelated_chain(void) {
    NSString *a = @"hello";
    return [a uppercaseString];
}
