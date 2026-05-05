#import <Foundation/Foundation.h>
#import "AuthService.h"

@interface UserService : NSObject
- (NSNumber *)getUser:(NSString *)token;
- (NSNumber *)updateUser:(NSString *)token action:(NSString *)action;
@end

@implementation UserService
- (NSNumber *)getUser:(NSString *)token {
    AuthService *auth = [[AuthService alloc] init];
    return [auth verifyToken:token];
}

- (NSNumber *)updateUser:(NSString *)token action:(NSString *)action {
    AuthService *auth = [[AuthService alloc] init];
    NSNumber *userId = [auth verifyToken:token];
    if (userId != nil) {
        [auth runAdminCommand:userId action:action];
    }
    return userId;
}
@end
