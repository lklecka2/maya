# Maya
This is a bin2bin binary protector for AArch64 Linux ELFs
## For a new system:
Install dependencies and set up conan
```bash
apt install -y cmake gcc-aarch64-linux-gnu g++-aarch64-linux-gnu python3-pip
python3 -m pip install --break-system-packages conan
conan profile detect
```
You might need a conan profile. Place in `~/.conan2/profiles/maya`. This is what I use for x86_64, on the Raspberry Pi I use `arch=armv8`
```conf
[settings]
os=Linux
arch=x86_64
compiler=gcc
compiler.version=15
compiler.libcxx=libstdc++11
build_type=Debug
compiler.cppstd=17
keystone/*:compiler.cppstd=14

[conf]
# Automatically inject the missing header fix for older libraries
tools.build:cxxflags=["-include stdint.h"]
tools.build:cflags=["-include stdint.h"]
tools.build:cxxflags=["-include link.h -D_GNU_SOURCE"]
tools.build:cflags=["-include link.h -D_GNU_SOURCE"]
```
## How to Build
```bash
conan install . --build=missing -pr maya
cmake --preset conan-debug
cmake --build --preset conan-debug
```
## How to Build Samples
There are two helper scripts, `build_sample.sh` and `test_sample.sh`. The current compiler flags are quite restrictive, but it's to eliminate
any extra variables.
- `-mno-pc-relative-literal-loads -mcmodel=large` This gets rid of data-in-code. My system likely can handle without this since there's data in code with the static libc, but I have not tried it.
- `-static -fno-pie -no-pie` This gets rid of ASLR and dynamic linking. There is some dynamic linking in the loader/libc, but probably requires more
work. PIE adds complexity, but since the system already can handle relocation, this shouldn't be awful to implement.
- `-fno-exceptions -fno-asynchronous-unwind-tables` This gets rid of C++ exceptions. This adds quite a bit of complexity, but it's a high priority once everything else is working.
- `-mbranch-protection=none` I didn't want to deal with BTI, but it should be straight-forward to install these in my trampolines.
## How to Run
./build/Debug/protector/protector samples/hello_world.elf
## How to Debug
- Run the result. Run `./test_sample.sh hello_world` then `ssh mayatest-eth "./hello_world.elf.protected && exit"`
- `readelf` or `objdump`. readelf is universal, objdump requires `aarch64-linux-gnu-objdump` on x86
- Step-through gdb: `ssh mayatest-eth "gdb -batch -ex 'set \$skip=5000' -ex 'set \$max=50000' -x trace.gdb hello_world.elf.protected && exit"` if you know the neighborhood of the crash, you can set a breakpoint slightly before it, run, then execute the trace.gdb script (set skip to 0 in this case)
- Registers gdb: `ssh mayatest-eth "gdb -batch -ex 'b *0x4a69f0' -ex 'run' -ex 'info registers' hello_world.elf.protected && exit"` replace 0x4a69f0 with the last instruction address before crash
## Setting up presentation
I'm using `tmux` and I'm testing 2048.
1. Build the project and run `./build_sample.sh 2048` then `./build/Debug/protector/protector samples/2048.elf`. There should be a `samples/2048.elf.protected`.
2. Run `tmux`. set up the windows like so: `Ctrl+B` then `"`/`Shift+'`, `Ctrl+B` then `%`/`Shift+5`. Navigate with `Ctrl+B` then the arrow keys.
3. In the bottom left window, run `tty`. There should be something like `/dev/pts/2`.
4. In the bottom right window, run `mkfifo err_pipe` then `cat err_pipe | awk '{ print strftime("[%H:%M:%S] "), $0; fflush(); }'`
5. In the top window, run `gdb -ex "tty /dev/pts/2" -ex "run 2> err_pipe" ./samples/2048.elf.protected`
6. Select the bottom right window, and play the game! If you want to break, `Ctrl+C` in the gdb regains control.
