#!/bin/sh
# Release hook (build): builds the release archives at the tag.
# The shared release workflow runs this file, at a fixed path, when it exists.
set -eu
bash scripts/release.sh "$TAG"
