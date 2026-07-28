#include <stdio.h>

static _Thread_local int tls_value = 40;

__attribute__((noinline, noipa, used)) int protected_tls_add(int value) {
    return tls_value + value;
}

int main(void) {
    int result = protected_tls_add(2);
    printf("tls_access=%d\n", result);
    return result == 42 ? 0 : 1;
}
