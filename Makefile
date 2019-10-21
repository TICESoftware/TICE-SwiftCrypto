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

lint: Sources Package.swift TICECrypto.podspec
	./lint.sh $(version)

version: lint
	git push
	git push --tags
	pod repo push --allow-warnings AnbionPods
