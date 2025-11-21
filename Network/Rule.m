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

- (BOOL)matchesHostname:(NSString *)hostname
             remotePort:(NSInteger)remotePort
              localPort:(NSInteger)localPort
               protocol:(NSString *)protocol
              direction:(NETrafficDirection)direction {
    // 1. 方向匹配（你的规则可能只针对 outbound）
    if (self.direction != NETrafficDirectionAny && self.direction != direction) {
        return NO;
    }

    // 2. 协议匹配（支持 "tcp", "udp", "any"）
    if (![self.protocols containsObject:@"any"] &&
        ![self.protocols containsObject:protocol]) {
        return NO;
    }

    // 3. 端口和主机匹配（遍历 tuples）
    for (FirewallTuple *tuple in self.tuples) {
        // 主机匹配：支持通配符或精确匹配
        BOOL hostMatch = [self hostMatches:tuple.dstHost target:hostname];
        
        // 端口匹配：支持 "0" 表示任意端口，或具体端口列表
        BOOL portMatch = [self portMatches:tuple.dstPorts targetPort:remotePort];
        
        if (hostMatch && portMatch) {
            return YES;
        }
    }
    
    return NO;
}

// 辅助方法：主机匹配（简单版：精确 or 通配符 *.example.com）
- (BOOL)hostMatches:(NSString *)pattern target:(NSString *)target {
    if ([pattern isEqualToString:@"*"] || [pattern isEqualToString:target]) {
        return YES;
    }
    // 支持 *.example.com → 匹配 a.example.com, b.c.example.com
    if ([pattern hasPrefix:@"*."]) {
        NSString *suffix = [pattern substringFromIndex:2]; // 去掉 "*."
        return [target hasSuffix:suffix] &&
               [target rangeOfString:@"."].location != NSNotFound; // 至少有一个点
    }
    return NO;
}

// 辅助方法：端口匹配
- (BOOL)portMatches:(NSArray<NSString *> *)allowedPorts targetPort:(NSInteger)target {
    if ([allowedPorts containsObject:@"0"] || [allowedPorts containsObject:@"*"]) {
        return YES;
    }
    for (NSString *portStr in allowedPorts) {
        NSInteger port = [portStr integerValue];
        if (port == target) {
            return YES;
        }
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
