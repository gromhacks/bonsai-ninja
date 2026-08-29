// language_gauntlet Objective-C entry — reads one GCDWebServer request, then
// dispatches through a pipeline that exercises every
// idiomatic Obj-C flow construct (classes + categories, blocks,
// @try/@catch/@finally, dictionary literals, NSArray enumerations,
// properties, protocols).
#import <Foundation/Foundation.h>
#import <GCDWebServer/GCDWebServer.h>
#import "../Routing/CommandRouter.h"

void handle_request(GCDWebServerDataRequest *request) {
    // SOURCE — the typed GCDWebServer parameter carries remote HTTP data.
    NSString *raw = request.text ?: @"";
    NSString *user = @"remote";

    // Dictionary literal carrying the tainted cmd.
    NSDictionary *envelope = @{
        @"kind":   @"run",
        @"cmd":    raw,
        @"user":   user,
        @"length": @([raw length]),
        @"extras": @[raw],
    };

    startPipeline(envelope);
}

int main(int argc, const char *argv[]) {
    (void)argc; (void)argv;
    @autoreleasepool {
        handle_request(nil);
    }
    return 0;
}
