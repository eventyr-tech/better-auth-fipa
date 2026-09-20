#import <React/RCTBridgeModule.h>
#import <DeviceAttestationSpec/DeviceAttestationSpec.h>
#import "DeviceAttestation-Swift.h"

@interface RCT_EXTERN_MODULE(DeviceAttestationAppAttest, NSObject)
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
RCT_EXTERN_METHOD(resetKey:(NSString *)storagePrefix
                  credentialScope:(NSString *)credentialScope
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(removeKey:(NSString *)storagePrefix
                  credentialScope:(NSString *)credentialScope
                  expectedKeyId:(NSString *)expectedKeyId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
@end

@implementation DeviceAttestationAppAttest (TurboModule)
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeDeviceAttestationSpecJSI>(params);
}
@end
