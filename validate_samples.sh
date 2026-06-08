#!/bin/bash
set -euo pipefail

protector="${MAYA_PROTECTOR:-./build/Debug/protector/protector}"
slot_strategy="${MAYA_SLOT_STRATEGY:-runtime-allocator}"
eh_slot_strategy="${MAYA_EH_SLOT_STRATEGY:-fixed-per-function}"
qemu=""
native_aarch64=""
if [ "$(uname -m)" = "aarch64" ]; then
  native_aarch64=1
fi
if command -v qemu-aarch64 >/dev/null 2>&1; then
  qemu="$(command -v qemu-aarch64)"
elif command -v qemu-aarch64-static >/dev/null 2>&1; then
  qemu="$(command -v qemu-aarch64-static)"
fi

run_protected() {
  local binary="$1"
  if [ -n "$native_aarch64" ]; then
    chmod +x "$binary"
    "$binary"
  elif [ -n "$qemu" ]; then
    "$qemu" -L /usr/aarch64-linux-gnu "$binary"
  fi
}

samples=(
  hello_world
  basic_funcs
  nested_calls
  recursion
  func_ptr
  callback_sort
  switch_table
  string_ops
  struct_heavy
  bitfield
  float_math
  thread_stress
)

for sample in "${samples[@]}"; do
  MAYA_SAMPLE_VARIANT=static ./build_sample.sh "$sample"
  "$protector" --slot-strategy "$slot_strategy" "samples/$sample.elf"
  run_protected "samples/$sample.elf.protected"
done

for sample in hello_world basic_funcs nested_calls func_ptr switch_table; do
  MAYA_SAMPLE_VARIANT=pie ./build_sample.sh "$sample"
  "$protector" --slot-strategy "$slot_strategy" "samples/$sample.pie.elf"
  run_protected "samples/$sample.pie.elf.protected"
done

MAYA_SAMPLE_VARIANT=exceptions ./build_sample.sh cpp_exceptions
"$protector" --slot-strategy "$eh_slot_strategy" "samples/cpp_exceptions.exceptions.elf"
run_protected "samples/cpp_exceptions.exceptions.elf.protected"

MAYA_SAMPLE_VARIANT=exceptions ./build_sample.sh cpp_asio_threads
"$protector" --slot-strategy "$eh_slot_strategy" "samples/cpp_asio_threads.exceptions.elf"
run_protected "samples/cpp_asio_threads.exceptions.elf.protected"

if command -v upx >/dev/null 2>&1; then
  cp samples/hello_world.pie.elf.protected /tmp/maya-hello-upx
  upx -q /tmp/maya-hello-upx
  run_protected /tmp/maya-hello-upx
else
  echo "Skipping UPX pack check: upx is not installed."
fi

if [ -z "$native_aarch64" ] && [ -z "$qemu" ]; then
  echo "Skipping runtime checks: not native AArch64 and qemu-aarch64 is not installed."
fi
