// Complex ObjC fixture: classes, categories, protocols, try/catch,
// branches, loops.
#import <Foundation/Foundation.h>

@interface UserRepository : NSObject
@property (nonatomic, strong) NSMutableDictionary *users;
- (NSString *)findUser:(NSNumber *)userId;
- (BOOL)loadAllUsers;
@end

@implementation UserRepository

- (instancetype)init {
    self = [super init];
    if (self) {
        _users = [NSMutableDictionary dictionary];
    }
    return self;
}

- (NSString *)findUser:(NSNumber *)userId {
    if ([self.users objectForKey:userId] != nil) {
        return [self.users objectForKey:userId];
    }
    return nil;
}

- (BOOL)loadAllUsers {
    @try {
        for (int i = 0; i < 10; i++) {
            NSString *key = [NSString stringWithFormat:@"user_%d", i];
            [self.users setObject:key forKey:@(i)];
        }
        return YES;
    } @catch (NSException *e) {
        NSLog(@"load failed: %@", e);
        return NO;
    }
}

@end

NSString *escapeSQL(NSString *input) {
    return [input stringByReplacingOccurrencesOfString:@"'" withString:@"''"];
}

void dispatchToken(NSString *token) {
    if ([token length] == 0) {
        return;
    }
    if ([token hasPrefix:@"admin_"]) {
        runAdmin(token);
    } else {
        runUser(token);
    }
}

void processBatch(NSArray *tokens) {
    for (NSString *token in tokens) {
        dispatchToken(token);
    }
}

void runAdmin(NSString *token) {
    system([[NSString stringWithFormat:@"admin-task %@", token] UTF8String]);
}

void runUser(NSString *token) {
    system([[NSString stringWithFormat:@"user-task %@", token] UTF8String]);
}
