//
//  AppFilterProvider.m
//  Network
//
//  Created by azimgd on 13.06.2023.
//

#import "AppFilterProvider.h"

@implementation AppFilterProvider

- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable))completionHandler {
#ifdef __BLOOM__ //bloom.h
    // 初始化布隆过滤器：预计 10 万个恶意域名，误判率 1%
    if (bloom_init2(&g_maliciousDomainBloom, 100000, 0.01) != 0) {
        NSLog(@"Failed to init bloom filter");
        completionHandler([NSError errorWithDomain:@"BloomInitError" code:1 userInfo:nil]);
        return;
    }
    // 加载恶意域名（从本地文件、网络或硬编码）
    [self loadMaliciousDomainsIntoBloom:&g_maliciousDomainBloom];
#endif
    
#ifdef __JSON__
    //1.读取并解析 JSON 规则
    NSArray<FirewallRule *> *rules = [self loadFirewallRuleFromJson];
    if (rules) {
        //保存到成员变量
        self.firewallRules = rules;
        NSLog(@"Successfully loaded %lu firewall rules", (unsigned long)rules.count);
    } else {
        NSLog(@"Failed to load firewall rules. Using empty rule set.");
        self.firewallRules = @[];
    }
#endif
    // 2. 配置 Network Extension 过滤规则（捕获所有 TCP/UDP 出站流量）
    NENetworkRule *outboundRule = [[NENetworkRule alloc]
        initWithRemoteNetwork:nil remotePrefix:0
        localNetwork:nil localPrefix:0
        protocol:NENetworkRuleProtocolAny
        direction:NETrafficDirectionOutbound];

    // 入站规则在 iOS 上通常无效，可选保留（macOS 可能有用）
    NENetworkRule *inboundRule = [[NENetworkRule alloc]
        initWithRemoteNetwork:nil remotePrefix:0
        localNetwork:nil localPrefix:0
        protocol:NENetworkRuleProtocolAny
        direction:NETrafficDirectionInbound];

    NEFilterRule *outboundFilterRule = [[NEFilterRule alloc]
        initWithNetworkRule:outboundRule action:NEFilterActionFilterData];
    NEFilterRule *inboundFilterRule = [[NEFilterRule alloc]
        initWithNetworkRule:inboundRule action:NEFilterActionFilterData];

    NEFilterSettings *filterSettings = [[NEFilterSettings alloc]
        initWithRules:@[outboundFilterRule, inboundFilterRule]
        defaultAction:NEFilterActionAllow];

    // 🚀 3. 应用设置并启动过滤
    [self applySettings:filterSettings completionHandler:completionHandler];
    
    //4.处理出站数据包
    
}

#ifdef __BLOOM__
- (void)loadMaliciousDomainsIntoBloom:(struct bloom *)bloom {
    // 示例：从本地文件读取（实际可从 bundle 或安全服务器下载）
    NSString *path = [[NSBundle mainBundle] pathForResource:@"malicious_domains" ofType:@"txt"];
    NSString *content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    NSArray *domains = [content componentsSeparatedByString:@"\n"];
    
    NSString* newDomain = nil;
    for (NSString *domain in domains) {
        newDomain = [domain stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (newDomain.length > 0) {
            // 插入到布隆过滤器（注意：C 函数需要 const void* 和长度）
            bloom_add(bloom, [newDomain UTF8String], (int)[newDomain lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
        }
    }
}
#endif

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler
{
    completionHandler();
}

- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;

    // 1. 获取远程和本地端点信息
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint *)socketFlow.remoteEndpoint;
    NWHostEndpoint *localEndpoint  = (NWHostEndpoint *)socketFlow.localEndpoint;

    NSString *hostName = remoteEndpoint.hostname ?: @"";
    NSString *remotePortStr = remoteEndpoint.port ?: @"0";
    NSString *localPortStr  = localEndpoint.port ?: @"0";

    NSInteger remotePort = [remotePortStr integerValue];
    NSInteger localPort  = [localPortStr integerValue];

    // 2. 协议判断
    BOOL isTCP = (socketFlow.socketProtocol == NENetworkRuleProtocolTCP);
    BOOL isUDP = (socketFlow.socketProtocol == NENetworkRuleProtocolUDP);
    NSString *protoStr = isTCP ? @"tcp" : (isUDP ? @"udp" : @"other");

    // 3. 方向（通常 handleNewFlow 只处理 outbound，但保留判断）
    NETrafficDirection direction = socketFlow.direction;

    // 🔒 入站连接通常无法获取 hostname，直接放行（或丢弃）
    if (direction == NETrafficDirectionInbound) {
        // 可选：记录日志，但不拦截
        return [NEFilterNewFlowVerdict allowVerdict];
    }

    // 4. 布隆过滤器：拦截恶意域名（高优先级）
#ifdef __BLOOM__
    if (hostName.length > 0) {
        int result = bloom_check(&g_maliciousDomainBloom,
                                 [hostName UTF8String],
                                 (int)[hostName lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
        if (result == 1) {
            NSLog(@"🚨 BLOCKED by Bloom Filter: %@:%ld", hostName, (long)remotePort);
            return [NEFilterNewFlowVerdict dropVerdict];
        }
    }
#endif

    // 5. JSON 规则匹配（按优先级顺序）
#ifdef __JSON__
    for (FirewallRule *rule in self.firewallRules) {
        // 检查规则是否匹配当前流量:主机名、目的端口、本机端口、协议、方向
        if ([rule matchesHostname:hostName
                            remotePort:remotePort
                            localPort:localPort
                            protocol:protoStr
                            direction:direction]) {

            if ([rule.action isEqualToString:@"block"]) {
                NSLog(@"BLOCKED by rule (level=%ld): %@:%ld proto=%@",
                      (long)rule.level, hostName, (long)remotePort, protoStr);
                return [NEFilterNewFlowVerdict dropVerdict];
            } else if ([rule.action isEqualToString:@"allow"]) {
                // 显式允许，可提前放行（避免后续规则覆盖）
                NSLog(@"ALLOWED by rule (level=%ld): %@:%ld", (long)rule.level, hostName, (long)remotePort);
                return [NEFilterNewFlowVerdict allowVerdict];
            }
            // 其他 action 类型可扩展
        }
    }
#endif

    // 6. 默认行为：允许连接，但监控出站数据（用于日志/分析）
    NSLog(@"ℹ️ DEFAULT ALLOW: %@:%ld (%@)", hostName, (long)remotePort, protoStr);
    return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:NO
                                                      peekInboundBytes:0
                                                     filterOutbound:YES
                                                   peekOutboundBytes:64];
}
//本机向外发送的数据
- (NEFilterDataVerdict *)handleOutboundDataCompleteForFlow:(NEFilterFlow *)flow{
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint*)socketFlow.remoteEndpoint;

    NSString* _hostName = remoteEndpoint.hostname;
    NSString* _port = remoteEndpoint.port;
    
    NSLog(@"=====[%@:%@] has sent the flow=====",_hostName,_port);
    return [NEFilterDataVerdict allowVerdict];
}

//外部向本机发送的数据
- (NEFilterDataVerdict *)handleInboundDataCompleteForFlow:(NEFilterFlow *)flow{
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint*)socketFlow.remoteEndpoint;

    NSString* _hostName = remoteEndpoint.hostname;
    NSString* _port = remoteEndpoint.port;
    NSLog(@"=====[%@:%@] has received the flow=====",_hostName,_port);
    return [NEFilterDataVerdict allowVerdict];
}
#ifdef __JSON__
- (NSArray<FirewallRule *> *)loadFirewallRuleFromJson {
    // 1. 获取 JSON 路径（从当前 Extension 的 bundle 中读取）
    NSString *jsonPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"rule" ofType:@"json"];
    if (!jsonPath) {
        NSLog(@"rules.json not found in extension bundle. Check Target Membership!");
        return nil;
    }

    // 2. 读取文件数据
    NSData *jsonData = [NSData dataWithContentsOfFile:jsonPath];
    if (!jsonData || jsonData.length == 0) {
        NSLog(@"Failed to read rules.json or file is empty");
        return nil;
    }

    // 3. 解析 JSON
    NSError *error = nil;
    id jsonObject = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
    if (!jsonObject) {
        NSLog(@"Invalid JSON format: %@", error.localizedDescription);
        return nil;
    }

    // 4. 验证结构：确保 jsonObject 是字典，且包含 data.rules
    if (![jsonObject isKindOfClass:[NSDictionary class]]) {
        NSLog(@"JSON root is not a dictionary");
        return nil;
    }

    NSDictionary *dataDict = jsonObject[@"data"];
    if (![dataDict isKindOfClass:[NSDictionary class]]) {
        NSLog(@"Missing 'data' object in JSON");
        return nil;
    }

    NSArray *rawRules = dataDict[@"rules"];
    if (![rawRules isKindOfClass:[NSArray class]] || rawRules.count == 0) {
        NSLog(@"'data.rules' is missing or empty");
        return @[]; // 返回空数组而非 nil，避免后续 crash
    }

    // 5. 转换为 FirewallRule 对象
    NSMutableArray<FirewallRule *> *rules = [NSMutableArray array];
    for (NSDictionary *rawRule in rawRules) {
        FirewallRule *rule = [FirewallRule ruleWithDictionary:rawRule];
        if (rule) {
            [rules addObject:rule];
        } else {
            NSLog(@"Skipping invalid rule: %@", rawRule);
        }
    }

    // 6. 按优先级排序（level 升序：数值越小优先级越高）
    NSArray *sortedRules = [rules sortedArrayUsingSelector:@selector(compareByPriority:)];
    NSLog(@"Loaded %lu firewall rules", (unsigned long)sortedRules.count);

    return sortedRules;
}
#endif // __JSON__
@end
