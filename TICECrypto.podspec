Pod::Spec.new do |s|

  s.name          = "TICECrypto"
  s.version       = "30.0.0"
  s.summary       = "Crypto to be used in TICE projects."
  s.platform      = :ios, "12.0"
  s.swift_version = "5.0"

  s.homepage      = "https://ticeapp.com"

  s.author        = { "TICE Software UG (haftungsbeschränkt)" => "contact@ticeapp.com" }
  s.source        = { :git => "https://github.com/TICESoftware/TICE-SwiftCrypto.git", :tag => "#{s.version}" }
  s.license       = { :type => 'MIT' }

  s.source_files  = "Sources/**/*"

  s.dependency "TICEModels"
  s.dependency "X3DH"
  s.dependency "DoubleRatchet", '~> 2.0.0'
  s.dependency "AnbionSwiftJWT"
  s.dependency "Logging"

  s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  s.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }

end
