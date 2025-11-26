//
//  Rule.m
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/21.
//

#import "Rule.h"
#pragma mark - 复合键规则类 out udp 会转化为 out_udp
@implementation RuleCompositeKeyGenerator
+ (NSString *)compositeKeyWithDirection:(NSString *)direction protocol:(NSString *)protocol {
    // 统一格式（方向小写，协议小写），避免大小写导致的键不唯一
    NSString *lowerDir = [direction lowercaseString];
    NSString *lowerProto = [protocol lowercaseString];
    // 格式：方向_协议（如 "out_tcp"、"in_udp"）
    return [NSString stringWithFormat:@"%@_%@", lowerDir, lowerProto];
}

+ (NSDictionary<NSString *, NSString *> *)parseDirectionAndProtocolFromCompositeKey:(NSString *)compositeKey {
    NSArray *parts = [compositeKey componentsSeparatedByString:@"_"];
    if (parts.count != 2) return nil;
    return @{
        @"direction": parts[0],
        @"protocol": parts[1]
    };
}
@end

///ip和域名存储类
@implementation fiveINetTuple

- (instancetype)initWithIpStart:(uint32_t)ipStart
                         ipEnd:(uint32_t)ipEnd
                     portStart:(uint16_t)portStart
                       portEnd:(uint16_t)portEnd
                      hostName:(NSString *)hostName {
    if (self = [super init]) {
        _ipStart = ipStart;
        _ipEnd = ipEnd;
        _portStart = portStart;
        _portEnd = portEnd;
        _hostName = [hostName copy];
    }
    return self;
}
@end

///防火墙具体规则类
@implementation FirewallRule

- (instancetype)init {
    // 提供一个安全的默认初始化（虽然通常应使用指定初始化器）
    return [self initWithDirection:FlowDirectionOutbound
                          protocol:@[]
                       fiveTuples:@[]
                      processName:nil
                      processPath:nil
                    developerName:nil
                            allow:YES];
}

- (instancetype)initWithDirection:(FlowDirection)direction
                         protocol:(NSArray<NSNumber *> *)protocolTypes // 建议参数名与属性一致
                     fiveTuples:(NSArray<fiveINetTuple *> *)fiveTuples
                    processName:(nullable NSString *)processName
                    processPath:(nullable NSString *)processPath
                  developerName:(nullable NSString *)developerName
                          allow:(BOOL)allow {
    if (self = [super init]) {
        _direction = direction;
        _protocolTypes = [protocolTypes copy]; // 强制 copy
        _fiveTuples = [fiveTuples copy];
        _processName = processName;
        _processPath = processPath;
        _developerName = developerName;
        _allow = allow;
    }
    return self;
}


- (BOOL)isDNSRule {
    return YES;
}

+ (NSArray<FirewallRule *> *)rulesWithDictionary:(NSDictionary *)dict {
    // 1. 解析 direction
    NSString *dirStr = dict[@"direction"];
    if (![dirStr isEqualToString:@"out"] && ![dirStr isEqualToString:@"in"]) {
        NSLog(@"Invalid direction: %@", dirStr);
        return @[];
    }
    FlowDirection direction = [dirStr isEqualToString:@"out"] ? FlowDirectionOutbound : FlowDirectionInbound;

    // 2. 解析 action
    NSString *action = dict[@"action"];
    BOOL allow = [action isEqualToString:@"pass"]; // "block" → NO

    // 3. 解析元数据
    NSString *policyName = dict[@"policy_name"];
    NSString *policyId = dict[@"policy_id"];
    NSNumber *levelNum = dict[@"level"];
    BOOL shouldReport = [[dict objectForKey:@"report"] boolValue];
    NSString *title = dict[@"chinese"][@"title"];
    NSString *suggestion = dict[@"chinese"][@"suggestion"];

    // 4. ✅ 一次性解析所有协议
    NSMutableArray<NSNumber *> *protocolTypes = [NSMutableArray array];
    NSString *protoStr = dict[@"proto"];
    if ([protoStr isKindOfClass:[NSString class]]) {
        NSArray<NSString *> *protoList = [protoStr componentsSeparatedByString:@"|"];
        for (NSString *p in protoList) {
            if ([p isEqualToString:@"tcp"]) {
                [protocolTypes addObject:@(TransportProtocolTCP)];
            } else if ([p isEqualToString:@"udp"]) {
                [protocolTypes addObject:@(TransportProtocolUDP)];
            } else if ([p isEqualToString:@"icmp"]) {
                [protocolTypes addObject:@(TransportProtocolICMP)];
            }
            // 忽略未知协议
        }
    }
    if (protocolTypes.count == 0) {
        NSLog(@"No valid protocols in rule");
        return @[];
    }

    // 5. ✅ 一次性解析所有五元组
    NSMutableArray<fiveINetTuple *> *tuples = [NSMutableArray array];
    NSArray *rawTuples = dict[@"tuples"];
    if ([rawTuples isKindOfClass:[NSArray class]]) {
        for (NSDictionary *t in rawTuples) {
            NSString *host = t[@"dst_host"];
            NSArray *ports = t[@"dst_port"];
            if (![ports isKindOfClass:[NSArray class]]) continue;

            for (NSString *portSpec in ports) {
                uint16_t start, end;
                if ([portSpec containsString:@"-"]) {
                    NSArray *parts = [portSpec componentsSeparatedByString:@"-"];
                    if (parts.count == 2) {
                        start = (uint16_t)[parts[0] integerValue];
                        end = (uint16_t)[parts[1] integerValue];
                    } else {
                        continue;
                    }
                } else {
                    start = end = (uint16_t)[portSpec integerValue];
                }

                fiveINetTuple *tuple = [[fiveINetTuple alloc]
                    initWithIpStart:0
                           ipEnd:0
                       portStart:start
                         portEnd:end
                       hostName:host ?: @""];
                [tuples addObject:tuple];
            }
        }
    }

    // 6. ✅ 创建单条规则（支持多协议）
    FirewallRule *rule = [[FirewallRule alloc]
        initWithDirection:direction
                 protocol:protocolTypes   // ← 传入完整协议数组
             fiveTuples:tuples
            processName:nil
            processPath:nil
          developerName:nil
                  allow:allow];

    // 7. 设置元数据
    rule.policyName = policyName;
    rule.policyId = policyId;
    rule.level = [levelNum integerValue];
    rule.shouldReport = shouldReport;
    rule.localizedTitle = title;
    rule.localizedSuggestion = suggestion;

    // 8. 返回单元素数组
    return @[rule];
}

@end
///规则管理类
@implementation FirewallRuleManager

+ (instancetype)sharedManager {
    static FirewallRuleManager *instance = nil;
    static dispatch_once_t onceToken;
    //保证多线程下数据一致性
    dispatch_once(&onceToken, ^{
        instance = [[FirewallRuleManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    //初始化内部数据结构
    if (self = [super init]) {
        _ruleGroups = [NSMutableDictionary dictionary];
        _syncQueue = dispatch_queue_create("com.bordercontrol.rulemanager.sync", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)addRule:(FirewallRule *)rule {
    dispatch_sync(self.syncQueue, ^{
        for (NSNumber *protoNum in rule.protocolTypes) {
            TransportProtocol proto = (TransportProtocol)[protoNum unsignedIntegerValue];
            
            NSString *dirStr = (rule.direction == FlowDirectionOutbound) ? @"out" : @"in";
            NSString *protoStr = nil;
            switch (proto) {
                case TransportProtocolTCP:
                    protoStr = @"tcp";
                    break;
                case TransportProtocolUDP:
                    protoStr = @"udp";
                    break;
                case TransportProtocolICMP:
                    protoStr = @"icmp";
                    break;
                default:
                    continue; // 跳过无效协议
            }
            
            NSString *key = [RuleCompositeKeyGenerator compositeKeyWithDirection:dirStr protocol:protoStr];
            NSMutableArray<FirewallRule *> *group = self.ruleGroups[key];
            if (!group) {
                group = [NSMutableArray array];
                self.ruleGroups[key] = group;
            }
            [group addObject:rule];
        }
    });
}

- (void)removeAllRules {
    dispatch_sync(self.syncQueue, ^{
        [self.ruleGroups removeAllObjects];
    });
}


- (NSArray<FirewallRule *> *)rulesForDirection:(FlowDirection)direction
                                      protocol:(TransportProtocol)protocol {
    NSString *dirStr = (direction == FlowDirectionOutbound) ? @"out" : @"in";
    NSString *protoStr = nil;
    switch (protocol) {
        case TransportProtocolTCP:   protoStr = @"tcp"; break;
        case TransportProtocolUDP:   protoStr = @"udp"; break;
        case TransportProtocolICMP:  protoStr = @"icmp"; break;
        default: return @[];
    }
    
    NSString *key = [RuleCompositeKeyGenerator compositeKeyWithDirection:dirStr protocol:protoStr];
    
    __block NSArray<FirewallRule *> *result = @[];
    dispatch_sync(self.syncQueue, ^{
        result = [self.ruleGroups[key] copy] ?: @[];
    });
    return result;
}

//返回所有规则列表
- (NSArray<FirewallRule *> *)allRules {
    __block NSMutableSet<FirewallRule *> *uniqueRules = [NSMutableSet set];
    dispatch_sync(self.syncQueue, ^{
        for (NSArray<FirewallRule *> *group in [self.ruleGroups allValues]) {
            [uniqueRules addObjectsFromArray:group];
        }
    });
    return [uniqueRules allObjects];
}

// FirewallRuleManager.m
- (FirewallRule *_Nullable)firstMatchedRuleForHostname:(NSString *)hostname
                                              remotePort:(NSInteger)remotePort
                                               localPort:(NSInteger)localPort
                                                protocol:(TransportProtocol)protocol
                                               direction:(FlowDirection)direction {
    // 1. 获取该 direction + protocol 下的所有规则
    NSArray<FirewallRule *> *candidateRules = [self rulesForDirection:direction protocol:protocol];
    if (candidateRules.count == 0) {
        NSLog(@"firstMatchedRuleForHostname : candidataeRules is nil");
        return nil;
    }

    FirewallRule *bestMatch = nil;
    NSInteger highestLevel = NSNotFound;

    for (FirewallRule *rule in candidateRules) {
        BOOL matched = NO;

        if (direction == FlowDirectionOutbound) {
            // 出站：检查每个 fiveTuple 的 hostName 和 remotePort 是否在范围内
            for (fiveINetTuple *tuple in rule.fiveTuples) {
                // 端口匹配：remotePort ∈ [portStart, portEnd]
                if (remotePort < tuple.portStart || remotePort > tuple.portEnd) {
                    continue;
                }

                // 主机名匹配（支持 nil 表示任意）
                if (tuple.hostName == nil) {
                    matched = YES;
                    break;
                }

                // 支持通配符 *.example.com
                if ([self hostName:hostname matchesPattern:tuple.hostName]) {
                    matched = YES;
                    break;
                }
            }
        } else {
            // 入站：只匹配本地端口（localPort），忽略 hostName（因不可靠）
            for (fiveINetTuple *tuple in rule.fiveTuples) {
                if (localPort >= tuple.portStart && localPort <= tuple.portEnd) {
                    matched = YES;
                    break;
                }
            }
        }

        if (matched) {
            // 选择 level 最高的规则（数值越大优先级越高）
            if (rule.level > highestLevel) {
                highestLevel = rule.level;
                bestMatch = rule;
            }
        }
    }

    return bestMatch;
}

// 主机名通配符匹配工具方法（支持 *.example.com）
- (BOOL)hostName:(NSString *)host matchesPattern:(NSString *)pattern {
    if ([host isEqualToString:pattern]) {
        return YES;
    }

    // 支持前缀通配符 *.example.com
    if ([pattern hasPrefix:@"*."]) {
        NSString *suffix = [pattern substringFromIndex:2]; // 去掉 "*."
        if ([host length] > [suffix length] && [host hasSuffix:suffix]) {
            // 确保至少有一个子域（不能直接匹配 example.com）
            NSRange dotRange = [host rangeOfString:@"." options:NSBackwardsSearch];
            if (dotRange.location != NSNotFound && dotRange.location > 0) {
                NSString *prefix = [host substringToIndex:dotRange.location];
                if (prefix.length > 0) {
                    return YES;
                }
            }
        }
    }

    // TODO: 可扩展支持更多模式（如 api.*.com 需要正则）
    return NO;
}
@end
