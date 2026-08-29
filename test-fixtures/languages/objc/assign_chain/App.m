// Assignment-chain audit fixture (Objective-C).
// Uses fgets() as source (objc.source.stdin_fgets) + system() as
// cmdi sink (objc.cmdi.system). NSDictionary subscript-read shape
// is a separate adapter audit (Task #265).
#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

extern void runInOtherFile(const char *cmd);

static const char *CONST_OK = "ls /tmp";

static char *passthrough(char *x) { return x; }
static char *wrap(char *x) {
    static char buf[1024];
    snprintf(buf, sizeof(buf), "wrapped:%s", x);
    return buf;
}
static char *combine(char *acc, const char *item) {
    static char buf[1024];
    snprintf(buf, sizeof(buf), "%s:%s", acc, item);
    return buf;
}

@interface Bag : NSObject
@property (nonatomic, assign) char *payload;
@end
@implementation Bag
@end

void chainSimple(void) {
    // POSITIVE
    char tmp[256];
    fgets(tmp, sizeof(tmp), stdin);
    system(tmp);
}

void chainMultiHop(void) {
    // POSITIVE
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    char *t1 = buf;
    char *t2 = passthrough(t1);
    char *t3 = wrap(t2);
    char *t4 = passthrough(t3);
    system(t4);
}

void chainBranchJoin(BOOL cond) {
    // POSITIVE on tainted leg
    char buf[256];
    char *t;
    if (cond) {
        fgets(buf, sizeof(buf), stdin);
        t = buf;
    } else {
        t = "safe-static";
    }
    system(t);
}

void chainLoopCarried(NSArray *items) {
    // POSITIVE
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    char *acc = buf;
    for (NSString *item in items) {
        acc = combine(acc, [item UTF8String]);
    }
    system(acc);
}

void chainFieldWrite(void) {
    // POSITIVE
    Bag *bag = [[Bag alloc] init];
    static char buf[256];
    fgets(buf, sizeof(buf), stdin);
    bag.payload = buf;
    system(bag.payload);
}

void chainCleanConstant(void) {
    // NEGATIVE
    char buf[256];
    (void)fgets(buf, sizeof(buf), stdin);
    system(CONST_OK);
}

void chainCrossFile(void) {
    // POSITIVE
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    runInOtherFile(buf);
}
