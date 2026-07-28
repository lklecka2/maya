#include <cstdio>
#include <stdexcept>

__attribute__((noinline, noipa, used)) static int leaf(int value) {
    if (value == 7) {
        throw std::runtime_error("maya exception path");
    }
    return value + 1;
}

static int middle(int value) {
    return leaf(value) * 2;
}

int main() {
    int result = 0;
    try {
        result += middle(3);
        result += middle(7);
    } catch (const std::exception& ex) {
        std::printf("caught:%s result:%d\n", ex.what(), result);
        return result == 8 ? 0 : 2;
    }
    return 1;
}
