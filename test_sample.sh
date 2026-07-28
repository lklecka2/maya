#!/bin/bash
set -euo pipefail

if [ -z "$1" ]; then
    echo "Usage: $0 <protected_exec_name>"
    exit 1
fi

remote="${MAYA_REMOTE:-opi}"
ssh_config="${MAYA_SSH_CONFIG:-$HOME/.ssh/config}"
input="samples/$1.elf"
output="$input.protected"
echo "Protecting $input"
./build/Debug/protector/maya protect "$input"
echo "Sending $output to $remote"
scp -F "$ssh_config" -q "$output" "$remote:/tmp/$1.elf.protected.tmp"
ssh -F "$ssh_config" "$remote" "mv '/tmp/$1.elf.protected.tmp' '/tmp/$1.elf.protected';'/tmp/$1.elf.protected'"
