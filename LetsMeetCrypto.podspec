Pod::Spec.new do |s|

  s.name          = "LetsMeetCrypto"
  s.version       = "2.0.5"
  s.summary       = "Crypto to be used in Let's Meet projects."
  s.platform      = :ios, "11.0"
  s.swift_version = "4.2"

  s.homepage      = "http://letsmeet.anbion.de"

  s.author        = { "Anbion" => "letsmeet@anbion.de" }
  s.source        = { :git => "git@github.com:AnbionApps/letsmeet-crypto.git", :tag => "#{s.version}" }

  s.source_files  = "Sources/**/*"

  s.dependency "LetsMeetModels"
  s.dependency "SwiftJWT"

end
