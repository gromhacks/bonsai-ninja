#import <Foundation/Foundation.h>
#import <string.h>

extern void transformAndForward(const char *value);

void runPipeline(const char *payload) {
    char wrapped[512];
    snprintf(wrapped, sizeof(wrapped), "[%s]", payload);
    transformAndForward(wrapped);
}
