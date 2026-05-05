// Pipeline — exercises Objective-C's idiomatic flow constructs:
// blocks, enumerateObjectsUsingBlock, @try/@catch/@finally,
// fast-enumeration (for-in), NSMutableDictionary, NSPredicate,
// switch on enum.
#import <Foundation/Foundation.h>

extern NSDictionary *persist(NSDictionary *envelope);

// Block typedef — closure reducer joining tokens with `sep`.
typedef NSString *(^JoinerBlock)(NSString *acc, NSString *tok);

static JoinerBlock makeJoiner(NSString *sep) {
    return ^NSString *(NSString *acc, NSString *tok) {
        if ([acc length] == 0) return tok;
        return [NSString stringWithFormat:@"%@%@%@", acc, sep, tok];
    };
}

NSDictionary *orchestrate(NSDictionary *envelope) {
    NSString *cmd = envelope[@"cmd"];
    NSString *user = envelope[@"user"];

    // Fast-enumeration (for-in) — walk every tainted token.
    NSMutableArray<NSString *> *tokens = [NSMutableArray array];
    for (NSString *part in [cmd componentsSeparatedByString:@" "]) {
        NSString *trimmed = [part stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([trimmed length] > 0) {
            [tokens addObject:trimmed];
        }
    }

    // Block-based reduce — taint rides the accumulator.
    JoinerBlock joiner = makeJoiner(@" ");
    __block NSString *joined = @"";
    [tokens enumerateObjectsUsingBlock:^(NSString *tok, NSUInteger idx, BOOL *stop) {
        (void)idx; (void)stop;
        joined = joiner(joined, tok);
    }];

    // switch on NSString equality via if-else chain.
    NSString *routed;
    NSString *kind = envelope[@"kind"];
    if ([kind isEqualToString:@"run"]) {
        routed = [NSString stringWithFormat:@"%@", joined];
    } else if ([kind isEqualToString:@"eval"]) {
        routed = [joined stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    } else {
        routed = joined;
    }

    // @try / @catch / @finally — taint survives every branch.
    NSMutableDictionary *valid = [envelope mutableCopy];
    @try {
        if ([routed length] == 0) {
            @throw [NSException exceptionWithName:@"Empty" reason:@"empty" userInfo:nil];
        }
        valid[@"cmd"] = routed;
        valid[@"user"] = user;
    } @catch (NSException *ex) {
        (void)ex;
        valid[@"cmd"] = routed;
        valid[@"user"] = user;
    } @finally {
        // no-op — present so the adapter sees the finally clause.
    }

    return persist(valid);
}
