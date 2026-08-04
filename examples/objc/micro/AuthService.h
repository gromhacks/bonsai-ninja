#import <Foundation/Foundation.h>

@interface AuthService : NSObject
- (NSNumber *)verifyToken:(NSString *)token;
- (void)runAdminCommand:(NSNumber *)userId action:(NSString *)action;
@end
