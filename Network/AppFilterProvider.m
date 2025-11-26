//
//  AppFilterProvider.m
//  Network
//
//  Created by azimgd on 13.06.2023.
//

#import "AppFilterProvider.h"

@implementation AppFilterProvider

#pragma mark - Lifecycle

- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable))completionHandler {
    // 1️⃣ 初始化规则管理器（单例已自动创建）
    FirewallRuleManager *rulesManager = [FirewallRuleManager sharedManager];
    // 2️⃣ 加载并注册 JSON 规则（内部会清空旧规则）
    [self loadAndRegisterFirewallRules];
    // 4️⃣ 配置 NEFilterSettings：拦截所有 TCP/UDP 流量以触发 handleNewFlow
//    NENetworkRule *tcpOut = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                       localNetwork:nil localPrefix:0
//                                                         protocol:NENetworkRuleProtocolTCP
//                                                         direction:NETrafficDirectionOutbound];
//    NENetworkRule *tcpIn  = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                       localNetwork:nil localPrefix:0
//                                                         protocol:NENetworkRuleProtocolTCP
//                                                         direction:NETrafficDirectionInbound];
//    NENetworkRule *udpOut = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                       localNetwork:nil localPrefix:0
//                                                         protocol:NENetworkRuleProtocolUDP
//                                                         direction:NETrafficDirectionOutbound];
//    NENetworkRule *udpIn  = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0
//                                                       localNetwork:nil localPrefix:0
//                                                         protocol:NENetworkRuleProtocolUDP
//                                                         direction:NETrafficDirectionInbound];
//
//    NEFilterRule *tcpOutRule = [[NEFilterRule alloc] initWithNetworkRule:tcpOut action:NEFilterActionFilterData];
//    NEFilterRule *tcpInRule  = [[NEFilterRule alloc] initWithNetworkRule:tcpIn  action:NEFilterActionFilterData];
//    NEFilterRule *udpOutRule = [[NEFilterRule alloc] initWithNetworkRule:udpOut action:NEFilterActionFilterData];
//    NEFilterRule *udpInRule  = [[NEFilterRule alloc] initWithNetworkRule:udpIn  action:NEFilterActionFilterData];
//
//    NSArray<NEFilterRule *> *allRules = @[tcpOutRule, tcpInRule, udpOutRule, udpInRule];
//    NEFilterSettings *settings = [[NEFilterSettings alloc] initWithRules:allRules defaultAction:NEFilterActionAllow];

    NENetworkRule* networkRule = [
      [NENetworkRule alloc]
      initWithRemoteNetwork:nil
      remotePrefix:0
      localNetwork:nil
      localPrefix:0
      protocol:NENetworkRuleProtocolAny
      direction:NETrafficDirectionOutbound
    ];
    NEFilterRule* filterRule = [
      [NEFilterRule alloc]
      initWithNetworkRule:networkRule
      action:NEFilterActionFilterData
    ];
    NEFilterSettings* filterSettings = [
      [NEFilterSettings alloc]
      initWithRules:@[filterRule]
      defaultAction:NEFilterActionAllow
    ];

    [self applySettings:filterSettings completionHandler:^(NSError * _Nullable error) {
      completionHandler(error);
    }];
//    // 5️⃣ 应用设置
//    [self applySettings:settings completionHandler:^(NSError * _Nullable error) {
//        if (error) {
//            NSLog(@"Failed to start filter: %@", error.localizedDescription);
//        } else {
//            NSLog(@"Network filter started successfully");
//        }
//        completionHandler(error);
//    }];
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    completionHandler();
}

#pragma mark - Rule Loading

- (void)loadAndRegisterFirewallRules {
    NSString *jsonPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"rule" ofType:@"json"];
    if (!jsonPath) {
        NSLog(@"rule.json not found in extension bundle. Check Target Membership!");
        return;
    }

    NSData *jsonData = [NSData dataWithContentsOfFile:jsonPath];
    if (!jsonData || jsonData.length == 0) {
        NSLog(@"Failed to read rule.json or file is empty");
        return;
    }

    NSError *error = nil;
    id jsonObject = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
    if (!jsonObject || ![jsonObject isKindOfClass:[NSDictionary class]]) {
        NSLog(@"Invalid JSON root: %@", error.localizedDescription);
        return;
    }

    NSDictionary *dataDict = jsonObject[@"data"];
    NSArray *rawRules = dataDict[@"rules"];
    if (![rawRules isKindOfClass:[NSArray class]] || rawRules.count == 0) {
        NSLog(@"No rules in 'data.rules'");
        return;
    }

    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    [manager removeAllRules]; // 清空前一次规则

    NSUInteger total = 0;
    for (NSDictionary *rawRule in rawRules) {
        NSArray<FirewallRule *> *rules = [FirewallRule rulesWithDictionary:rawRule];
        for (FirewallRule *rule in rules) {
            [manager addRule:rule];
            total++;
        }
    }

    NSLog(@"Loaded and registered %lu firewall rule objects", (unsigned long)total);
}

- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if (![flow isKindOfClass:[NEFilterSocketFlow class]]) {
        NSLog(@"[FLOW] Non-socket flow, allowing.");
        return [NEFilterNewFlowVerdict allowVerdict];
    }

    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
    NWHostEndpoint *remoteEP = (NWHostEndpoint *)socketFlow.remoteEndpoint;
    NWHostEndpoint *localEP  = (NWHostEndpoint *)socketFlow.localEndpoint;

    NSString *remoteHostname = remoteEP.hostname ?: @"(null)";
    NSInteger remotePort = [remoteEP.port integerValue];
    NSInteger localPort  = [localEP.port integerValue];
    NETrafficDirection direction = socketFlow.direction;

    NSString *directionStr = (direction == NETrafficDirectionOutbound) ? @"OUT" : @"IN";
    NSString *protoStr = @"";
    TransportProtocol proto;
    if (socketFlow.socketProtocol == NENetworkRuleProtocolTCP) {
        proto = TransportProtocolTCP;
        protoStr = @"TCP";
    } else if (socketFlow.socketProtocol == NENetworkRuleProtocolUDP) {
        proto = TransportProtocolUDP;
        protoStr = @"UDP";
    } else {
        protoStr = @"OTHER";
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    
    // 🔍 打印完整流信息
    NSLog(@"\n[NEW FLOW] %@ %@\n"
          "  Local:  %ld\n"
          "  Remote: (%@):%ld\n"
          "  Hostname: %@\n"
          "  Rule check...",
          directionStr, protoStr,
          (long)localPort,
          remoteHostname, (long)remotePort,
          remoteHostname);

    // 入站放行
    if (direction == NETrafficDirectionInbound) {
        NSLog(@"[ALLOW] Inbound flow auto-allowed.");
        return [NEFilterNewFlowVerdict allowVerdict];
    }

    FirewallRuleManager *manager = [FirewallRuleManager sharedManager];
    FirewallRule *matchedRule = [manager firstMatchedRuleForHostname:remoteHostname
                                                           remotePort:remotePort
                                                            localPort:localPort
                                                             protocol:proto
                                                            direction:FlowDirectionOutbound];
//
//    if (matchedRule) {
//        if (!matchedRule.allow) {
//            NSLog(@"[BLOCK] Blocked by rule: %@", matchedRule.policyName ?: @"N/A");
//            return [NEFilterNewFlowVerdict dropVerdict];
//        } else {
//            NSLog(@"[ALLOW] Allowed by rule: %@", matchedRule.policyName ?: @"N/A");
//            return [NEFilterNewFlowVerdict allowVerdict];
//        }
//    }

    NSLog(@"[ALLOW] No matching rule, default allow.");
    return [NEFilterNewFlowVerdict allowVerdict];
}

// 可选：数据流回调（通常不需要修改）
- (NEFilterDataVerdict *)handleOutboundDataCompleteForFlow:(NEFilterFlow *)flow {
    NSLog(@"handleOutboundDataCompleteForFlow");
    return [NEFilterDataVerdict allowVerdict];
}

- (NEFilterDataVerdict *)handleInboundDataCompleteForFlow:(NEFilterFlow *)flow {
    NSLog(@"handleInboundDataCompleteForFlow");
    return [NEFilterDataVerdict allowVerdict];
}

@end
