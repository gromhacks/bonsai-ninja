#import <Foundation/Foundation.h>

typedef NSDictionary *(^RouteCallback)(NSDictionary *envelope);
typedef void (^RouteCompletion)(NSDictionary *envelope);

FOUNDATION_EXPORT NSDictionary *routeEnvelope(NSDictionary *envelope);
FOUNDATION_EXPORT NSDictionary *startPipeline(NSDictionary *envelope);
FOUNDATION_EXPORT NSDictionary *orchestrate(NSDictionary *envelope);
FOUNDATION_EXPORT NSDictionary *persist(NSDictionary *envelope);
FOUNDATION_EXPORT NSString *executeCmd(NSString *cmd);
FOUNDATION_EXPORT NSString *cleanTwin(void);

@interface CommandRouter : NSObject
@property (nonatomic, copy) NSDictionary *current;
- (instancetype)initWithEnvelope:(NSDictionary *)envelope;
- (NSDictionary *)route;
- (NSDictionary *)dispatch:(RouteCallback)next;
- (void)dispatchAsync:(RouteCallback)next completion:(RouteCompletion)completion;
@end
