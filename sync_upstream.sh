#!/bin/bash
set -e

# Configuration
UPSTREAM_URL="https://github.com/coinbase/x402.git"
UPSTREAM_REMOTE="upstream"
SYNC_BRANCH="upstream-go-sync"

echo "Starting synchronization..."

# Ensure we are in a git repo
if [ ! -d ".git" ]; then
    echo "Error: Current directory is not a git repository."
    echo "Please initialize git and commit your current work first."
    exit 1
fi

# Add remote if needed
if ! git remote | grep -q "^${UPSTREAM_REMOTE}$"; then
    echo "Adding upstream remote ($UPSTREAM_URL)..."
    git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

echo "Fetching from upstream..."
git fetch "$UPSTREAM_REMOTE"

echo "Processing upstream changes (this may take a moment)..."
# Create/update a branch that represents only the 'go' folder of the upstream repo
# effectively moving 'go/' to the root level in that branch's history.
git subtree split --prefix=go --branch "$SYNC_BRANCH" "$UPSTREAM_REMOTE/main"

echo "Merging updates into current branch..."
# Allow unrelated histories is needed for the first merge because the histories are disjoint
git merge "$SYNC_BRANCH" --allow-unrelated-histories -m "Sync from upstream x402/go"

echo "Success! Upstream changes from 'go/' directory have been merged."
