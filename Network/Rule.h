//
//  Rule.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/21.
//

#import <Foundation/Foundation.h>

@interface FirewallTuple : NSObject
// 目标（远程）
@property (nonatomic, copy) NSString *dstHost;        // 域名，如 @"*.feishu.cn"
@property (nonatomic, copy) NSString *dstIP;          // IP 地址或 CIDR，如 @"192.168.1.0/24"
@property (nonatomic, copy) NSArray<NSString *> *dstPorts; // @[@"80", @"443"]

// 源（本地）
@property (nonatomic, copy) NSString *srcIP;           // 如 @"10.0.0.5" 或 @"10.0.0.0/24"
@property (nonatomic, copy) NSArray<NSString *> *srcPorts; // @[@"50000-60000"]

@end

@interface FirewallRule : NSObject
//优先级
@property (nonatomic , assign) NSInteger level;
//方向：in / out
@property (nonatomic , copy) NSString* direction;
//协议：tcp/udp/icmp
@property (nonatomic , copy) NSArray<NSString*> *protocols;

@property (nonatomic, copy) NSString *action;            // @"allow" / @"block"
//五元组
@property (nonatomic, copy) NSArray<FirewallTuple *> *tuples;

+ (instancetype)ruleWithDictionary:(NSDictionary *)dict;

- (NSComparisonResult)compareByPriority:(FirewallRule *)other;
@end
