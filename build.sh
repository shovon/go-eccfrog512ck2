#!/bin/bash
BINARY_NAME="eccfrog"
PLATFORMS=("linux/amd64" "linux/arm64" "windows/amd64" "windows/386" "darwin/amd64" "darwin/arm64")

for platform in "${PLATFORMS[@]}"
do
    GOOS=${platform%%/*}
    GOARCH=${platform##*/}
    OUTPUT="${BINARY_NAME}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi
    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -o "build/$OUTPUT" cmd/main.go
done