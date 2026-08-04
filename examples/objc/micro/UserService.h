#import <Foundation/Foundation.h>
#import "AuthService.h"

@interface UserService : NSObject
- (NSNumber *)getUser:(NSString *)token;
- (NSNumber *)updateUser:(NSString *)token action:(NSString *)action;
@end
