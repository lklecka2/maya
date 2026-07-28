#include <stdint.h>
#include <stdio.h>

static volatile int bias = 7;

__attribute__((noinline)) int protected_leaf(int value, int rounds) {
    int acc = value + bias;
    for (int i = 0; i < rounds; ++i) {
        if ((i & 1) == 0) acc = acc * 3 + 11;
        else acc = acc - i;
    }
    return acc < 0 ? -acc : acc;
}

int main(void) {
    int result = protected_leaf(5, 6);
    printf("leaf=%d\n", result);
    return result == 444 ? 0 : 1;
}
