/* Tests: recursive calls, deep stack frames, tail recursion, mutual recursion */
#include <stdio.h>
#include <stdint.h>

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

static int is_even(unsigned n);
static int is_odd(unsigned n);

static int is_even(unsigned n) {
    if (n == 0) return 1;
    return is_odd(n - 1);
}

static int is_odd(unsigned n) {
    if (n == 0) return 0;
    return is_even(n - 1);
}

int ackermann(int m, int n) {
    if (m == 0) return n + 1;
    if (n == 0) return ackermann(m - 1, 1);
    return ackermann(m - 1, ackermann(m, n - 1));
}

int main(void) {
    printf("fib(10)=%d\n", fibonacci(10));
    printf("fib(20)=%d\n", fibonacci(20));
    printf("fact(10)=%d\n", factorial(10));
    printf("fact(12)=%d\n", factorial(12));
    printf("is_even(42)=%d\n", is_even(42));
    printf("is_odd(37)=%d\n", is_odd(37));
    printf("ack(3,4)=%d\n", ackermann(3, 4));
    return 0;
}
