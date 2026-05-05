#import <Foundation/Foundation.h>
#import "UserService.h"

@interface Gateway : NSObject
- (NSDictionary *)handleRequestWithToken:(NSString *)token action:(NSString *)action;
@end

@implementation Gateway
- (NSDictionary *)handleRequestWithToken:(NSString *)token action:(NSString *)action {
    UserService *svc = [[UserService alloc] init];
    id user = [svc getUser:token];
    id result = [svc updateUser:token action:action];
    return @{@"user": user ?: [NSNull null], @"result": result ?: [NSNull null]};
}
@end
