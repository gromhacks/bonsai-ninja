#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>

void executor(const char *cmd) {
    system(cmd);
}

void run_cb(void (*cb)(const char *), const char *value) {
    cb(value);
}

void passToCallback(void) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    run_cb(executor, buf);
}
