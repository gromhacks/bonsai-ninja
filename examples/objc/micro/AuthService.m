#import <Foundation/Foundation.h>

@interface AuthService : NSObject
- (NSNumber *)verifyToken:(NSString *)token;
- (void)runAdminCommand:(NSNumber *)userId action:(NSString *)action;
@end

@implementation AuthService
- (NSNumber *)verifyToken:(NSString *)token {
    NSString *query = [NSString stringWithFormat:@"SELECT user_id FROM tokens WHERE token = '%@'", token];
    // sink: SQL injection via format string
    NSLog(@"%@", query);
    return @1;
}

- (void)runAdminCommand:(NSNumber *)userId action:(NSString *)action {
    // sink: command injection via shell concatenation
    NSString *cmd = [NSString stringWithFormat:@"notify-admin %@", action];
    system([cmd UTF8String]);
}
@end
