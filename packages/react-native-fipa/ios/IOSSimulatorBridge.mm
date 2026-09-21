#import <React/RCTBridgeModule.h>
#import <DeviceAttestationSpec/DeviceAttestationSpec.h>
#import "DeviceAttestation-Swift.h"

@interface RCT_EXTERN_MODULE(DeviceAttestationIOSSimulator, NSObject)
RCT_EXTERN_METHOD(getKey:(NSString *)storagePrefix
                  credentialScope:(NSString *)credentialScope
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(getOrCreateKey:(NSString *)storagePrefix
                  credentialScope:(NSString *)credentialScope
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(generateEvidence:(NSString *)keyId
                  clientData:(NSString *)clientData
                  operation:(NSString *)operation
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(removeKey:(NSString *)storagePrefix
                  credentialScope:(NSString *)credentialScope
                  expectedKeyId:(NSString *)expectedKeyId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
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
@end

@implementation DeviceAttestationIOSSimulator (TurboModule)
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeIOSSimulatorSpecJSI>(params);
}
@end
