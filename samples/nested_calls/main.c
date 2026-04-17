/* Tests: deeply nested function calls (exercises ODL refcount tracking),
   variadic functions, functions with many parameters (stack spill),
   indirect calls through struct members */
#include <stdio.h>
#include <stdarg.h>

struct TenInts { int a, b, c, d, e, f, g, h, i, j; };
static int sum10(struct TenInts v) {
    return v.a + v.b + v.c + v.d + v.e + v.f + v.g + v.h + v.i + v.j;
}

static int va_sum(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int total = 0;
    for (int i = 0; i < count; i++) {
        total += va_arg(ap, int);
    }
    va_end(ap);
    return total;
}

static double va_weighted_sum(int count, ...) {
    va_list ap;
    va_start(ap, count);
    double total = 0.0;
    for (int i = 0; i < count; i++) {
        double weight = va_arg(ap, double);
        int value = va_arg(ap, int);
        total += weight * value;
    }
    va_end(ap);
    return total;
}

static int layer_a(int x);
static int layer_b(int x);
static int layer_c(int x);
static int layer_d(int x);
static int layer_e(int x);

static int layer_a(int x) { return layer_b(x + 1) + 1; }
static int layer_b(int x) { return layer_c(x + 1) + 2; }
static int layer_c(int x) { return layer_d(x + 1) + 3; }
static int layer_d(int x) { return layer_e(x + 1) + 4; }
static int layer_e(int x) { return x * 2; }

typedef struct {
    const char *name;
    int (*fn)(int, int);
} Command;

static int cmd_add(int a, int b) { return a + b; }
static int cmd_mul(int a, int b) { return a * b; }
static int cmd_max(int a, int b) { return a > b ? a : b; }
static int cmd_min(int a, int b) { return a < b ? a : b; }

int main(void) {
    printf("sum10=%d\n", sum10((struct TenInts){1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));

    printf("va_sum(5)=%d\n", va_sum(5, 10, 20, 30, 40, 50));
    printf("va_sum(3)=%d\n", va_sum(3, 100, 200, 300));

    printf("va_weighted=%.1f\n", va_weighted_sum(3,
           0.5, 10, 0.3, 20, 0.2, 30));

    printf("nested=%d\n", layer_a(0));
    printf("nested=%d\n", layer_a(10));

    Command cmds[] = {
        {"add", cmd_add},
        {"mul", cmd_mul},
        {"max", cmd_max},
        {"min", cmd_min},
    };

    for (int i = 0; i < 4; i++) {
        printf("%s(7,3)=%d\n", cmds[i].name, cmds[i].fn(7, 3));
    }

    return 0;
}
