#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <protected_exec_name>"
    exit 1
fi

echo "Patching samples/$1.elf"
./build/Debug/protector/protector samples/$1.elf
echo "Sending samples/$1.elf.protected"
chmod +x samples/$1.elf.protected
scp ./samples/$1.elf.protected mayatest-eth:~
# ssh mayatest-eth "./$1.elf.protected"
