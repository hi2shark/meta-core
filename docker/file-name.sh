#!/bin/sh
os="clash-meta-nw-linux-"
case $TARGETPLATFORM in
    "linux/amd64")
        arch="amd64-v1"
        ;;
    "linux/arm64")
        arch="arm64"
        ;;
    *)
        echo "Unknown architecture"
        exit 1
        ;;
esac
file_name="$os$arch-$(cat bin/version.txt)"
echo "$file_name"
