#!/bin/bash
set -e

# Configuration
REPO_URL="https://github.com/coinbase/x402.git"
TEMP_DIR="/var/tmp/x402_sync_temp"
TARGET_DIR=$(pwd)

echo "Starting synchronization from $REPO_URL..."

# Cleanup any previous runs
if [ -d "$TEMP_DIR" ]; then
    echo "Cleaning up unexpected temporary directory..."
    rm -rf "$TEMP_DIR"
fi

# Clone repository
echo "Cloning repository..."
git clone --depth 1 "$REPO_URL" "$TEMP_DIR"

# Sync go directory
# Using rsync to update existing files and add new ones
echo "Syncing 'go' directory to $TARGET_DIR..."
if command -v rsync &> /dev/null; then
    rsync -av "$TEMP_DIR/go/" "$TARGET_DIR/"
else
    echo "rsync not found, falling back to cp..."
    cp -R "$TEMP_DIR/go/." "$TARGET_DIR/"
fi

# Cleanup
echo "Cleaning up..."
rm -rf "$TEMP_DIR"

echo "Synchronization complete!"
