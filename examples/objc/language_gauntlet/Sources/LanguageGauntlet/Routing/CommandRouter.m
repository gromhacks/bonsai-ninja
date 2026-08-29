#import "CommandRouter.h"

@implementation CommandRouter

- (instancetype)initWithEnvelope:(NSDictionary *)envelope {
    self = [super init];
    if (self) {
        _current = [envelope copy];
    }
    return self;
}

- (NSDictionary *)snapshot {
    NSMutableDictionary *copy = [self.current mutableCopy];
    copy[@"cmd"] = self.current[@"cmd"] ?: @"";
    return [copy copy];
}

- (NSDictionary *)route {
    NSDictionary *routed = [self snapshot];
    for (NSUInteger attempt = 0; attempt < 2; ++attempt) {
        if (attempt == 0) {
            NSMutableDictionary *copy = [routed mutableCopy];
            copy[@"cmd"] = routed[@"cmd"] ?: @"";
            routed = [copy copy];
        } else {
            self.current = routed;
            routed = self.current;
        }
    }
    return routed;
}

- (NSDictionary *)dispatch:(RouteCallback)next {
    return next([self route]);
}

- (void)dispatchAsync:(RouteCallback)next completion:(RouteCompletion)completion {
    [[NSOperationQueue new] addOperationWithBlock:^{
        NSDictionary *result = [self dispatch:next];
        completion(result);
    }];
}

@end

NSDictionary *routeEnvelope(NSDictionary *envelope) {
    CommandRouter *router = [[CommandRouter alloc] initWithEnvelope:envelope];
    return [router route];
}

NSDictionary *startPipeline(NSDictionary *envelope) {
    return orchestrate(envelope);
}
