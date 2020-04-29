default: dev

clean:
	swift package clean
	swift package reset

update: Package.resolved
Package.resolved: Package.swift
	swift package update

xcode: TICECrypto.xcodeproj
TICECrypto.xcodeproj: Package.resolved
	swift package generate-xcodeproj --xcconfig-overrides config.xcconfig

dev: update xcode

build: Sources Package.swift TICECrypto.podspec
	swift build -Xcc -Ilibsodium-osx/include -Xlinker -Llibsodium-osx/lib

test: Sources Package.swift TICECrypto.podspec
	swift test -Xcc -Ilibsodium-osx/include -Xlinker -Llibsodium-osx/lib

lint: Sources Package.swift TICECrypto.podspec
	./lint.sh $(version)

version: build lint test
	git push
	git push --tags
	pod repo push AnbionPods
