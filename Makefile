default: dev

clean:
	swift package clean
	swift package reset

update: Package.resolved
Package.resolved: Package.swift
	swift package update

xcode: LetsMeetCrypto.xcodeproj
LetsMeetCrypto.xcodeproj: Package.resolved
	swift package generate-xcodeproj

dev: update xcode

lint: Sources Package.swift LetsMeetCrypto.podspec
	./lint.sh $(version)

version: lint
	git push
	git push --tags
	pod repo push --allow-warnings AnbionPods
