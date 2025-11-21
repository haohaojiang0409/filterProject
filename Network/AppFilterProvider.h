//
//  AppFilterProvider.h
//  Network
//
//  Created by azimgd on 13.06.2023.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "bloom.h"
#import "Rule.h"
#define __JSON__
#ifdef __BLOOM__
//静态布隆过滤器变量
static struct bloom g_maliciousDomainBloom;

#endif

@interface AppFilterProvider : NEFilterDataProvider
#ifdef __JSON__
@property (nonatomic , nonnull) NSArray<FirewallRule*> * firewallRules;
#endif
@end
