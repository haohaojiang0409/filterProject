//
//  AppDelegate.m
//  BorderControl
//
//  Created by azimgd on 13.06.2023.
//

#import "AppDelegate.h"

@interface AppDelegate ()


@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
  // Insert code here to initialize your application
    
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
  // Insert code here to tear down your application
}


- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app {
  return YES;
}

-(void)getJsonFromServer{
    //1.服务端的URL
    NSString* urlString = @"https://sp.pre.eagleyun.cn/api/agent/v1/edr/firewall_policy/get_firewall_detail_config";
    NSURL *url = [NSURL URLWithString:urlString];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    
    //2.获取token
    NSString *token = @"your_actual_token"; // ← 替换为真实 token（建议从 Keychain 读）
    NSString *cookieHeader = [NSString stringWithFormat:@"__Host-brizoo-token=%@", token];
    [request setValue:cookieHeader forHTTPHeaderField:@"Cookie"];
    
    NSURLSession *session = [NSURLSession sharedSession];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (error) {
            NSLog(@"❌ Fetch rules failed: %@", error);
            return;
        }
        
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        if (httpResp.statusCode != 200) {
            NSLog(@"❌ HTTP Error %ld", (long)httpResp.statusCode);
            return;
        }
        
        // 验证 JSON
        NSError *jsonError;
        id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (!jsonObject || jsonError) {
            NSLog(@"❌ Invalid JSON: %@", jsonError);
            return;
        }
        
        // 保存到 App Group 共享目录
        NSFileManager *fm = [NSFileManager defaultManager];
        NSURL *containerURL = [fm containerURLForSecurityApplicationGroupIdentifier:@"group.com.yourcompany.firewall"];
        if (!containerURL) {
            NSLog(@"❌ Failed to get App Group container");
            return;
        }
        
        NSURL *rulesFileURL = [containerURL URLByAppendingPathComponent:@"firewall_rules.json"];
        BOOL success = [data writeToURL:rulesFileURL atomically:YES];
        if (success) {
            NSLog(@"✅ Rules saved to: %@", rulesFileURL.path);
        } else {
            NSLog(@"❌ Failed to write rules file");
        }
    }];
    [task resume];
}

@end
