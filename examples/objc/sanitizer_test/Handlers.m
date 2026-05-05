// Objective-C sanitizer-fixture — parallel handlers per sink family.
#import <Foundation/Foundation.h>
#import <sqlite3.h>

@interface Handlers : NSObject
@property (assign) sqlite3 *db;
@end

@implementation Handlers

// --- SQL injection ----------------------------------------------------

- (void)sqlRaw:(NSString *)userId {
    sqlite3_stmt *stmt;
    NSString *q = [NSString stringWithFormat:@"SELECT * FROM users WHERE id = '%@'", userId];
    sqlite3_prepare_v2(self.db, [q UTF8String], -1, &stmt, NULL);
}

- (void)sqlSafe:(NSString *)userId {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(self.db, "SELECT * FROM users WHERE id = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, [userId UTF8String], -1, SQLITE_TRANSIENT);
}

// --- Open redirect ----------------------------------------------------

- (NSString *)redirectSafe:(NSString *)target {
    NSString *safe = [target stringByAddingPercentEncodingWithAllowedCharacters:
                      [NSCharacterSet URLQueryAllowedCharacterSet]];
    return [@"/next?to=" stringByAppendingString:safe];
}

@end
