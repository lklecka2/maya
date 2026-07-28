__attribute__((noinline, noipa, used)) int unsupported_sve(int value) {
    __asm__ volatile(".inst 0x2518e3e0"); /* ptrue p0.b */
    return value + 1;
}

int main(void) { return 0; }
