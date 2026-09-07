#import <Foundation/Foundation.h>
void parse_default(NSURLRequest *request) {
    NSData *input = [request HTTPBody];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:input];
    [parser parse];
}
void parse_external(NSURLRequest *request) {
    NSData *input = [request HTTPBody];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:input];
    parser.shouldResolveExternalEntities = YES;
    [parser parse];
}
