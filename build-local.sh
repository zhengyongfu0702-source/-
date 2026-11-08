#!/bin/bash
# 在 macOS 上本地编译出未签名 ipa。需要先装 Xcode 与 XcodeGen。
#   brew install xcodegen
#   ./build-local.sh
set -e
cd "$(dirname "$0")"

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "缺少 xcodegen，先执行： brew install xcodegen"
  exit 1
fi

xcodegen generate

xcodebuild \
  -project SXKC.xcodeproj \
  -scheme SXKC \
  -configuration Release \
  -sdk iphoneos \
  -derivedDataPath build \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGN_ENTITLEMENTS="" \
  build

APP="build/Build/Products/Release-iphoneos/SXKC.app"
rm -rf Payload SXKC-unsigned.ipa
mkdir -p Payload
cp -R "$APP" Payload/
zip -qry SXKC-unsigned.ipa Payload

echo ""
echo "完成： $(pwd)/SXKC-unsigned.ipa"
lipo -info "$APP/SXKC"
