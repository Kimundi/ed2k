#!/usr/bin/env bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd "$SCRIPT_DIR"

cargo install --force afl

mkdir -p samples
unzip -o samples.zip

cargo afl build

cargo afl fuzz -i samples -o out target/debug/ed2k-fuzzer
