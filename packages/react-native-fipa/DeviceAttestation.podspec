require "json"
package = JSON.parse(File.read(File.join(__dir__, "package.json")))
Pod::Spec.new do |s|
  s.name = "DeviceAttestation"
  s.module_name = "DeviceAttestation"
  s.version = package["version"]
  s.summary = package["description"]
  s.homepage = package["homepage"]
  s.license = package["license"]
  s.author = package["author"]
  s.platforms = { :ios => "15.1" }
  s.swift_version = "5.0"
  s.source = { :git => "https://github.com/eventyr-tech/better-auth-fipa.git", :tag => "react-native-v#{s.version}" }
  s.source_files = "ios/**/*.{h,mm,swift}"
  s.frameworks = "DeviceCheck", "CryptoKit", "Security", "LocalAuthentication", "AuthenticationServices", "UIKit"
  install_modules_dependencies(s)
end
