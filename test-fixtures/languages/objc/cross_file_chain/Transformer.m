#import <Foundation/Foundation.h>
#import <string.h>
#import <ctype.h>

extern void execute(const char *cmd);

void transformAndForward(const char *value) {
    char upper[512];
    strncpy(upper, value, sizeof(upper) - 1);
    upper[sizeof(upper) - 1] = '\0';
    for (size_t i = 0; upper[i]; i++) upper[i] = (char)toupper((unsigned char)upper[i]);
    execute(upper);
}
