#import <React/RCTBridgeModule.h>
#import <DeviceAttestationSpec/DeviceAttestationSpec.h>
#import "DeviceAttestation-Swift.h"

@interface RCT_EXTERN_MODULE(DeviceAttestationFirstPartyTransport, NSObject)
RCT_EXTERN_METHOD(randomToken:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(transaction:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(prepareDpop:(NSString *)alias resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(inspectDpop:(NSString *)alias resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(removeDpop:(NSString *)alias expectedThumbprint:(NSString *)expectedThumbprint resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(signDpop:(NSString *)alias
                  expectedThumbprint:(NSString *)expectedThumbprint
                  url:(NSString *)url
                  method:(NSString *)method
                  accessToken:(NSString * _Nullable)accessToken
                  nonce:(NSString * _Nullable)nonce
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(cancel:(NSString *)requestId resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(openBrowser:(NSString *)requestId
                  url:(NSString *)url
                  redirectUri:(NSString *)redirectUri
                  timeoutMilliseconds:(double)timeoutMilliseconds
                  allowInsecureLoopback:(BOOL)allowInsecureLoopback
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(cancelBrowser:(NSString *)requestId resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(send:(NSString *)requestId
                  url:(NSString *)url
                  method:(NSString *)method
                  headersJSON:(NSString *)headersJSON
                  body:(NSString * _Nullable)body
                  maximumResponseBytes:(double)maximumResponseBytes
                  timeoutMilliseconds:(double)timeoutMilliseconds
                  allowInsecureLoopback:(BOOL)allowInsecureLoopback
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
@end
@implementation DeviceAttestationFirstPartyTransport (TurboModule)
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeFirstPartyTransportSpecJSI>(params);
}
@end
