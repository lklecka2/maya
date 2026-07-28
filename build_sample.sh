#!/bin/bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <sample-name>" >&2
  exit 1
fi

sample="$1"
variant="${MAYA_SAMPLE_VARIANT:-pie}"
sample_dir="samples/$sample"

if [ ! -d "$sample_dir" ]; then
  echo "Unknown sample: $sample" >&2
  exit 1
fi

cc="${MAYA_AARCH64_CC:-aarch64-linux-gnu-gcc}"
cxx="${MAYA_AARCH64_CXX:-aarch64-linux-gnu-g++}"
sysroot="${MAYA_AARCH64_SYSROOT:-}"
if [ -z "$sysroot" ] && [ -d /opt/sysroots/fedora-aarch64 ]; then
  sysroot="/opt/sysroots/fedora-aarch64"
fi

gcc_libdir="${MAYA_AARCH64_GCC_LIBDIR:-}"
if [ -z "$gcc_libdir" ] && [ -n "$sysroot" ]; then
  detected="$(find "$sysroot/usr/lib/gcc" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | sort | tail -1 || true)"
  if [ -n "$detected" ]; then
    gcc_libdir="$detected"
  fi
fi

common_flags=(
  "${MAYA_OPT_LEVEL:--O0}"
)
c_flags=(
  -fno-exceptions
)
link_flags=(
  -pthread
  -lm
)

if [ -n "$sysroot" ]; then
  common_flags=(--sysroot="$sysroot" "${common_flags[@]}")
fi
if [ -n "$gcc_libdir" ]; then
  common_flags=(-L"$gcc_libdir" "${common_flags[@]}")
  link_flags=(-Wl,--whole-archive -lgcc_eh -Wl,--no-whole-archive "${link_flags[@]}")
fi

boost_include="${MAYA_BOOST_INCLUDE:-}"
if [ -z "$boost_include" ]; then
  boost_include="$(find "$HOME/.conan2" /tmp/maya-conan -path '*/include/boost/asio.hpp' -type f 2>/dev/null | sed 's#/boost/asio.hpp$##' | sort | tail -1 || true)"
fi
if [ -n "$boost_include" ]; then
  common_flags=(-Itools/asio_compat -I"$boost_include" "${common_flags[@]}")
fi

source=""
compiler="$cc"
if [ -f "$sample_dir/main.cpp" ]; then
  source="$sample_dir/main.cpp"
  compiler="$cxx"
  c_flags=()
  link_flags=(-Wl,--eh-frame-hdr "${link_flags[@]}")
  if [ -n "$sysroot" ] && [ -d "$sysroot/usr/include/c++" ]; then
    cxx_version="$(find "$sysroot/usr/include/c++" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -V | tail -1 || true)"
    if [ -n "$cxx_version" ]; then
      common_flags=(
        -isystem "$sysroot/usr/include/c++/$cxx_version"
        -isystem "$sysroot/usr/include/c++/$cxx_version/aarch64-redhat-linux"
        "${common_flags[@]}"
      )
    fi
  fi
elif [ -f "$sample_dir/main.c" ]; then
  source="$sample_dir/main.c"
else
  echo "Sample has no main.c or main.cpp: $sample" >&2
  exit 1
fi

case "$variant" in
  static)
    output="samples/$sample.elf"
    mode_flags=(-static -fno-pie -no-pie)
    ;;
  staticpie)
    output="samples/$sample.staticpie.elf"
    mode_flags=(-static-pie -fPIE)
    ;;
  nonpie)
    output="samples/$sample.nonpie.elf"
    mode_flags=(-fno-pie -no-pie)
    ;;
  pie)
    output="samples/$sample.pie.elf"
    mode_flags=(-fPIE -pie)
    ;;
  exceptions)
    output="samples/$sample.exceptions.elf"
    mode_flags=(-fno-pie -no-pie)
    link_flags=(-lgcc_s "${link_flags[@]}")
    ;;
  *)
    echo "Unsupported MAYA_SAMPLE_VARIANT=$variant; expected pie, staticpie, nonpie, static, or exceptions." >&2
    exit 1
    ;;
esac

if [ -n "${MAYA_BRANCH_PROTECTION:-}" ]; then
  common_flags+=("-mbranch-protection=$MAYA_BRANCH_PROTECTION")
fi

if [ "$variant" = "exceptions" ] && [ "$compiler" = "$cc" ]; then
  echo "exceptions variant requires a C++ sample: $sample" >&2
  exit 1
fi

"$compiler" \
  "${common_flags[@]}" \
  "${mode_flags[@]}" \
  "${c_flags[@]}" \
  "$source" \
  "${link_flags[@]}" \
  -o "$output"

echo "Built $output"
