module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: "android",
        packageImportPath:
          "import com.deviceattestation.DeviceAttestationPackage;",
        packageInstance: "new DeviceAttestationPackage()",
      },
    },
  },
};
