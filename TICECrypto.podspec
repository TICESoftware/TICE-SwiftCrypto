Pod::Spec.new do |s|

  s.name          = "TICECrypto"
  s.version       = "29.1.0"
  s.summary       = "Crypto to be used in TICE projects."
  s.platform      = :ios, "11.0"
  s.swift_version = "5.1"

  s.homepage      = "https://ticeapp.com"

  s.author        = { "TICE Software UG (haftungsbeschränkt)" => "contact@ticeapp.com" }
  s.source        = { :git => "https://github.com/TICESoftware/TICE-SwiftCrypto.git", :tag => "#{s.version}" }
  s.license       = { :type => 'MIT' }

  s.source_files  = "Sources/**/*"

  s.dependency "TICEModels"
  s.dependency "X3DH"
  s.dependency "DoubleRatchet"
  s.dependency "AnbionSwiftJWT"
  s.dependency "Logging"

end
