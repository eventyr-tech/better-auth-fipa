const {
  withDangerousMod,
  withMainApplication,
  withXcodeProject,
} = require("expo/config-plugins");
const fs = require("node:fs");
const path = require("node:path");
module.exports = function withLabDiagnostics(config) {
  config = withXcodeProject(config, (mod) => {
    if (config.ios?.bundleIdentifier !== "io.eventyr.attestationlab")
      throw new Error("iOS lab diagnostics require the dedicated lab bundle");
    const name = mod.modRequest.projectName;
    const source = `${name}/AttestationLabDiagnostics.m`;
    fs.copyFileSync(
      path.join(__dirname, "AttestationLabDiagnostics.m"),
      path.join(mod.modRequest.platformProjectRoot, source),
    );
    if (!mod.modResults.hasFile(source)) {
      mod.modResults.addSourceFile(
        source,
        {
          target: mod.modResults.getFirstTarget().uuid,
        },
        mod.modResults.findPBXGroupKey({ name }),
      );
    }
    return mod;
  });
  config = withMainApplication(config, (mod) => {
    if (config.android?.package !== "io.eventyr.attestationlab")
      throw new Error(
        "Android lab diagnostics require the dedicated test package",
      );
    mod.modResults.contents = mod.modResults.contents.replace(
      "PackageList(this).packages.apply {",
      "PackageList(this).packages.apply {\n          add(io.eventyr.attestationlab.AttestationLabPackage())",
    );
    if (
      !mod.modResults.contents.includes(
        "add(io.eventyr.attestationlab.AttestationLabPackage())",
      )
    )
      throw new Error("Could not register lab diagnostics");
    return mod;
  });
  return withDangerousMod(config, [
    "android",
    async (mod) => {
      const destination = path.join(
        mod.modRequest.platformProjectRoot,
        "app/src/main/java/io/eventyr/attestationlab",
      );
      fs.mkdirSync(destination, { recursive: true });
      fs.copyFileSync(
        path.join(__dirname, "AttestationLabPackage.kt"),
        path.join(destination, "AttestationLabPackage.kt"),
      );
      return mod;
    },
  ]);
};
