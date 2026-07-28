# Maya Protector

Maya is a bin-to-bin protector for Linux AArch64 ELF executables.

## Build

Install a C/C++ toolchain, CMake, an AArch64 cross compiler, Python, Conan 2, and xxd:

```bash
sudo apt update
sudo apt install \
  build-essential cmake python3 pipx xxd \
  gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
  binutils-aarch64-linux-gnu
pipx install conan
pipx ensurepath
```

Create a Conan profile appropriate for the build host:

```bash
conan export conan/recipes/capstone --version=5.0.7
conan install . --build=missing -pr maya
cmake --preset conan-debug
cmake --build --preset conan-debug
ctest --test-dir build/Debug --output-on-failure
```

The default build is V2-only and does not require Z3. To build the complete V3
and native-variant feature set:

```bash
conan install . --build=missing -pr maya \
  -o '&:with_v3=True' -s 'z3/*:compiler.cppstd=20'
cmake --preset conan-debug
cmake --build --preset conan-debug
```

## Protect a binary

The default command uses the production configuration.

```bash
MAYA_SAMPLE_VARIANT=static ./build_sample.sh hello_world
./build/Debug/protector/maya protect samples/hello_world.elf
```

This writes:

- `samples/hello_world.elf.protected`, the protected ELF
- `samples/hello_world.elf.protection.tsv`, including profile, selection,
  backend, transformation, artifact hash, permissions, and size-delta records.

Use `-o` to choose an output name:

```bash
./build/Debug/protector/maya protect input.elf -o release/app
```

## Analyze without writing a binary

```bash
./build/Debug/protector/maya analyze input.elf
```

The default report is `input.elf.analysis.tsv`. Analysis applies the same
selection and eligibility rules as protection.

## Advanced controls

Available options:

```text
--backend auto|fragments-only|compatibility
--functions GLOB
--exclude GLOB
--seed 64_HEX_CHARACTERS
--upx-compatible-layout
--verbose
```

V3-enabled builds additionally provide:

```text
--profile standard|experimental-v3
--native-variants | --no-native-variants
```

Run `maya protect --help` for the complete command reference.

## Test on AArch64

```bash
MAYA_SAMPLE_VARIANT=static ./build_sample.sh hello_world
./test_sample.sh hello_world
```
