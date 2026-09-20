// App-local fault injection. Included only by the opted-in lab config plugin.
#import <React/RCTBridgeModule.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>

@interface AttestationLabDiagnostics : NSObject <RCTBridgeModule>
@end

@implementation AttestationLabDiagnostics
RCT_EXPORT_MODULE();
+ (BOOL)requiresMainQueueSetup { return NO; }
RCT_REMAP_METHOD(loseDpopKey, loseDpopKey:(NSString *)slot
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject) {
  if (![[NSBundle mainBundle].bundleIdentifier isEqualToString:@"io.eventyr.attestationlab"] ||
      [slot rangeOfString:@"^[A-Za-z0-9_-]{43}$" options:NSRegularExpressionSearch].location == NSNotFound) {
    reject(@"lab_scope", @"Invalid lab account slot", nil);
    return;
  }
  LAContext *context = [LAContext new];
  context.interactionNotAllowed = YES;
  NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrLabel: @"com.dpop.secureenclave",
    (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    (__bridge id)kSecReturnAttributes: @YES,
    (__bridge id)kSecReturnRef: @YES,
    (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    (__bridge id)kSecUseAuthenticationContext: context
  };
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
  if (status != errSecSuccess) {
    reject(@"lab_lookup", @"Cannot inspect lab signing keys", nil);
    return;
  }
  NSArray *keys = CFBridgingRelease(result);
  NSMutableArray *matches = [NSMutableArray new];
  NSString *pattern = [NSString stringWithFormat:@"^com\\.dpop\\.secureenclave\\.fipa\\.v1\\.[A-Za-z0-9_-]{43}\\.%@$", slot];
  for (NSDictionary *key in keys) {
    NSString *tag = [[NSString alloc] initWithData:key[(__bridge id)kSecAttrApplicationTag] encoding:NSUTF8StringEncoding];
    if (tag && [tag rangeOfString:pattern options:NSRegularExpressionSearch].location != NSNotFound) [matches addObject:key];
  }
  if (matches.count != 1) {
    reject(@"lab_ambiguous", @"Expected exactly one signing key for the selected slot", nil);
    return;
  }
  // Delete this exact key reference only. No vault, App Attest, or other key writes.
  status = SecItemDelete((__bridge CFDictionaryRef)@{
    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
    (__bridge id)kSecValueRef: matches[0][(__bridge id)kSecValueRef],
    (__bridge id)kSecUseAuthenticationContext: context
  });
  if (status != errSecSuccess) {
    reject(@"lab_delete", @"Cannot delete selected signing key", nil);
    return;
  }
  resolve(@"Selected DPoP key deleted. Vault and App Attest references retained.");
}
@end
