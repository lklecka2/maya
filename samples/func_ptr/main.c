/* Tests: function pointers, indirect calls, arrays of function pointers,
   passing function pointers as arguments, typedef'd function types */
#include <stdio.h>
#include <stdlib.h>

typedef int (*binop_t)(int, int);

static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
static int divide(int a, int b) { return b != 0 ? a / b : 0; }
static int mod(int a, int b) { return b != 0 ? a % b : 0; }

static int apply(binop_t op, int a, int b) {
    return op(a, b);
}

static int apply_chain(binop_t *ops, int n_ops, int initial, int operand) {
    int result = initial;
    for (int i = 0; i < n_ops; i++) {
        result = ops[i](result, operand);
    }
    return result;
}

static binop_t select_op(char c) {
    switch (c) {
    case '+': return add;
    case '-': return sub;
    case '*': return mul;
    case '/': return divide;
    case '%': return mod;
    default:  return add;
    }
}

int main(void) {
    binop_t ops[] = {add, sub, mul, divide, mod};
    const char *names[] = {"add", "sub", "mul", "div", "mod"};

    for (int i = 0; i < 5; i++) {
        printf("%s(17,5)=%d\n", names[i], ops[i](17, 5));
    }

    printf("apply(add,10,3)=%d\n", apply(add, 10, 3));
    printf("apply(mul,10,3)=%d\n", apply(mul, 10, 3));

    binop_t chain[] = {add, mul, sub};
    printf("chain(0,+5,*5,-3)=%d\n", apply_chain(chain, 3, 0, 5));

    const char *ops_str = "+-*/%";
    for (int i = 0; ops_str[i]; i++) {
        binop_t op = select_op(ops_str[i]);
        printf("select('%c')(20,7)=%d\n", ops_str[i], op(20, 7));
    }

    return 0;
}
