from conan import ConanFile
from conan.tools.cmake import CMakeDeps, CMakeToolchain, cmake_layout


class MayaConan(ConanFile):
    name = "maya"
    version = "0.1.0"
    settings = "os", "arch", "compiler", "build_type"
    options = {"with_v3": [True, False]}
    default_options = {"with_v3": False}

    def requirements(self):
        self.requires("lief/0.16.2")
        self.requires("capstone/5.0.7")
        self.requires("keystone/0.9.2")
        self.requires("mbedtls/3.2.1")
        if self.options.with_v3:
            self.requires("z3/4.15.4")

    def configure(self):
        self.options["lief"].with_pe = False
        self.options["lief"].with_macho = False
        self.options["lief"].with_art = False
        self.options["lief"].with_dex = False
        self.options["lief"].with_vdex = False
        self.options["lief"].with_oat = False
        for architecture in (
            "arm", "x86", "mips", "ppc", "sparc", "sysz", "xcore", "m68k",
            "tms320c64x", "m680x", "evm", "mos65xx", "wasm", "bpf", "riscv",
            "sh", "tricore",
        ):
            setattr(self.options["capstone"], architecture, False)
        self.options["capstone"].arm64 = True

    def layout(self):
        cmake_layout(self)

    def generate(self):
        CMakeDeps(self).generate()
        toolchain = CMakeToolchain(self)
        toolchain.cache_variables["MAYA_ENABLE_V3"] = bool(self.options.with_v3)
        toolchain.cache_variables["MAYA_MBEDTLS_ROOT"] = str(
            self.dependencies["mbedtls"].package_folder
        )
        toolchain.generate()
