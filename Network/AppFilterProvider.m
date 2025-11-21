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
#ifdef ___JSON__
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow*)flow;
    
    // 1. 获取远程和本地端点信息
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint *)socketFlow.remoteEndpoint;
    NWHostEndpoint *localEndpoint  = (NWHostEndpoint *)socketFlow.localEndpoint;
    
    NSString *hostName = remoteEndpoint.hostname ?: @"";
    NSString *remotePortStr = remoteEndpoint.port ?: @"0";
    NSString *localPortStr  = localEndpoint.port ?: @"0";
    
    NSNumber *remotePort = @([remotePortStr integerValue]);
    NSNumber *localPort  = @([localPortStr integerValue]);
    NSData *processData = nil;
    // 2. 获取进程信息（如果可用）
    if (@available(macOS 13.0, *)) {
        processData = socketFlow.sourceProcessAuditToken;
    } else {
        // Fallback on earlier versions
    }
    // 注意：company（代码签名组织）需要额外通过 SecCode API 获取，此处简化
    
    // 3. 协议和方向
    BOOL isTCP = (socketFlow.socketProtocol == NENetworkRuleProtocolTCP);
    BOOL isUDP = (socketFlow.socketProtocol == NENetworkRuleProtocolUDP);
    // 判断协议类型
    NSString *protoStr = isTCP ? @"tcp" : (isUDP ? @"udp" : @"other");
    
    NETrafficDirection direction = socketFlow.direction; // inbound or outbound
    
    // 4. 布隆过滤器检查（原有逻辑）
#endif // ___JSON__
    
#ifdef __BLOOM__
    if (hostName.length > 0) {
        int result = bloom_check(&g_maliciousDomainBloom,
                                 [hostName UTF8String],
                                 (int)[hostName lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
        if (result == 1) {
            NSLog(@"🚨 BLOCKING malicious domain: %@", hostName);
            return [NEFilterNewFlowVerdict dropVerdict];
        }
    }
#endif
    
    NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow*)flow;
    NWHostEndpoint *remoteEndpoint = (NWHostEndpoint*)socketFlow.remoteEndpoint;
    
    NSString* _hostName = remoteEndpoint.hostname;
    NSString* _port = remoteEndpoint.port;
    
    NSLog(@"=====[%@:%@] has sent the flow=====",_hostName,_port);
    
    return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:64 filterOutbound:YES peekOutboundBytes:64];
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
    
    NSLog(@"=====[%@:%@] has sent the flow=====",_hostName,_port);
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
