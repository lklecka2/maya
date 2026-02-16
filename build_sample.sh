#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <sample_directory_name>"
    exit 1
fi

echo "Building samples/$1.elf"

aarch64-linux-gnu-gcc samples/"$1"/main.c -o samples/"$1".elf \
  -mno-pc-relative-literal-loads -mcmodel=large \
  -static -fno-pie -no-pie \
  -fno-exceptions -fno-asynchronous-unwind-tables \
  -mbranch-protection=none
