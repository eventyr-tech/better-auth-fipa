#import <React/RCTBridgeModule.h>
#import <DeviceAttestationSpec/DeviceAttestationSpec.h>
#import "DeviceAttestation-Swift.h"

@interface RCT_EXTERN_MODULE(DeviceAttestationSessionVault, NSObject)
RCT_EXTERN_METHOD(acquire:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  accessibility:(NSString *)accessibility
                  leaseMilliseconds:(double)leaseMilliseconds
                  preserveSession:(BOOL)preserveSession
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(commit:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  leaseId:(NSString *)leaseId
                  generation:(double)generation
                  identityJSON:(NSString * _Nullable)identityJSON
                  sessionJSON:(NSString * _Nullable)sessionJSON
                  recoverySessionJSON:(NSString * _Nullable)recoverySessionJSON
                  hasInteraction:(BOOL)hasInteraction
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(renew:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  leaseId:(NSString *)leaseId
                  generation:(double)generation
                  leaseMilliseconds:(double)leaseMilliseconds
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(abandon:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  leaseId:(NSString *)leaseId
                  generation:(double)generation
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(invalidate:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  accessibility:(NSString *)accessibility
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(discard:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  generation:(double)generation
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(saveIdentity:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  leaseId:(NSString *)leaseId
                  generation:(double)generation
                  identityJSON:(NSString *)identityJSON
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(clearSession:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  leaseId:(NSString *)leaseId
                  generation:(double)generation
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(release:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  leaseId:(NSString *)leaseId
                  generation:(double)generation
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(cancelInteraction:(NSString *)storageNamespace
                  slotId:(NSString *)slotId
                  accessibility:(NSString *)accessibility
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
@end

@implementation DeviceAttestationSessionVault (TurboModule)
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeSessionVaultSpecJSI>(params);
}
@end
