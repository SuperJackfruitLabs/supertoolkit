#!/bin/sh
# Release hook (ci-check): the gate's fallback when forge CI's result for the tag cannot be read.
# The shared release workflow runs this file, at a fixed path, when it exists.
set -eu
go test ./...
