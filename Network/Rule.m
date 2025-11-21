//
//  Rule.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/21.
//

#import "Rule.h"

@implementation FirewallTuple

-(NSString*)description {
    return [NSString stringWithFormat:@"<Tuple Host = %@ ports = %@>" , self.dstHost , self.dstPorts];
}
@end

@implementation FirewallRule

-(instancetype)init{
    if(self = [super init]){
        _protocols = @[];
        _tuples = @[];
    }
    return self;
}

//从字典中获取规则，保存到对象中
+(instancetype)ruleWithDictionary:(NSDictionary*)dict{
    FirewallRule* rule = [[FirewallRule alloc] init];
    
    //解析优先级以及其他成员
    rule.level = [dict[@"level"] integerValue];
    rule.direction = [dict[@"direction"] lowercaseString];
    rule.action = dict[@"action"];
    
    //解析字符串
    NSString* protoStr = dict[@"proto"];
    rule.protocols = [protoStr componentsSeparatedByString:@"|"];
    
    //解析tuples
    NSMutableArray* tuples = [NSMutableArray array];
    for(NSDictionary* d in dict[@"tuples"]){
        FirewallTuple* tuple = [[FirewallTuple alloc] init];
        tuple.dstHost = d[@"dst_host"];     // 域名
        tuple.dstIP   = d[@"dst_ip"];       // IP/CIDR
        tuple.srcIP   = d[@"src_ip"];       // 源 IP
        tuple.dstPorts = d[@"dst_port"] ?: @[@"0"];
        tuple.srcPorts = d[@"src_port"] ?: @[@"0"]; // 新增
        [tuples addObject:tuple];
    }
    rule.tuples = [tuples copy];
    return rule;
}

// 域名通配符匹配（简化版，支持 *.example.com）
- (BOOL)wildcardMatch:(NSString *)pattern host:(NSString *)host {
    if ([pattern isEqualToString:host]) return YES;
    if (![pattern hasPrefix:@"*."]) return NO;
    
    NSString *suffix = [pattern substringFromIndex:2]; // 去掉 "*."
    return [host hasSuffix:suffix] && [host rangeOfString:@"."].location != NSNotFound;
}

-(BOOL)matchesHostName:(NSString*)hostname port:(NSInteger)port protocol:(NSString*)proto direction:(NSString *)dir{
    if(self.direction && ![self.direction isEqualToString:@"any"]){
        return NO;
    }
    
    for(FirewallTuple* tuple in self.tuples){
        if(![self wildcardMatch:tuple host:hostname]){
            continue;
        }
        BOOL portMatch = NO;
        for(NSString* p in tuple.dstPorts){
            if ([p isEqualToString:@"0"] || [p integerValue] == port) {
               portMatch = YES;
               break;
            }
        }
        if(portMatch) return YES;
    }
    return NO;
}

///优先级排序
- (NSComparisonResult)compareByPriority:(FirewallRule *)other {
    if (self.level < other.level) return NSOrderedAscending;   // self 优先级更高
    if (self.level > other.level) return NSOrderedDescending;
    return NSOrderedSame;
}

@end
