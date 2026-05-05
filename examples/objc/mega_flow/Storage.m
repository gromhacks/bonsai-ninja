// Class hierarchy — Obj-C @interface / @implementation with
// inheritance, protocols, properties — all preserving taint on the
// way to the sink.
#import <Foundation/Foundation.h>

extern NSString *executeCmd(NSString *cmd);

@protocol Runnable <NSObject>
- (NSString *)run;
@end

@interface Repository : NSObject <Runnable>
@property (nonatomic, strong) NSDictionary *data;
- (instancetype)initWithData:(NSDictionary *)data;
- (NSString *)cmd;
@end

@implementation Repository
- (instancetype)initWithData:(NSDictionary *)data {
    self = [super init];
    if (self) {
        _data = data;
    }
    return self;
}

- (NSString *)cmd {
    return self.data[@"cmd"];
}

- (NSString *)run {
    NSString *c = [self cmd];
    return executeCmd(c);
}
@end

@interface AuditedRepository : Repository
@end

@implementation AuditedRepository
- (NSString *)run {
    // [super run] preserves taint across the inheritance chain.
    return [super run];
}
@end

NSDictionary *persist(NSDictionary *envelope) {
    AuditedRepository *repo = [[AuditedRepository alloc] initWithData:envelope];
    NSString *out = [repo run];
    return @{@"out": out ?: @""};
}
