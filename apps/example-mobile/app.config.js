module.exports = {
  expo: {
    name: "Attestation Example",
    slug: "device-attestation-example",
    version: "1.0.0",
    plugins: [
      ["expo-build-properties", { android: { minSdkVersion: 28 } }],
      ...(process.env.ATTESTATION_LAB_DIAGNOSTICS === "1"
        ? ["./diagnostics/with-lab-diagnostics.cjs"]
        : []),
    ],
    scheme: "com.example.deviceattestation",
    ios: {
      bundleIdentifier:
        process.env.EXAMPLE_IOS_BUNDLE_ID ?? "com.example.deviceattestation",
      entitlements: {
        "com.apple.developer.devicecheck.appattest-environment": "development",
      },
      infoPlist: { NSAppTransportSecurity: { NSAllowsLocalNetworking: true } },
    },
    android: {
      package:
        process.env.EXPO_PUBLIC_ANDROID_APPLICATION_ID ??
        "com.example.deviceattestation",
      versionCode: Number(process.env.ATTESTATION_LAB_VERSION_CODE ?? "1"),
    },
  },
};
