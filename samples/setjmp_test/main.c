/* Tests: setjmp/longjmp (non-local jumps), which exercises stack unwinding
   and register save/restore across protection boundaries */
#include <stdio.h>
#include <setjmp.h>

static jmp_buf escape;
static int depth;

static void deep_call(int n) {
    depth = n;
    if (n <= 0) {
        printf("deep_call: bottom reached, jumping back\n");
        longjmp(escape, 42);
    }
    printf("deep_call(%d) descending\n", n);
    deep_call(n - 1);
    printf("ERROR: returned from deep_call(%d)\n", n);
}

static jmp_buf error_jmp;

static int safe_divide(int a, int b) {
    if (b == 0) {
        longjmp(error_jmp, 1);
    }
    return a / b;
}

static jmp_buf outer, inner;

static void inner_func(void) {
    printf("inner_func: jumping to inner\n");
    longjmp(inner, 1);
}

static void outer_func(void) {
    if (setjmp(inner) == 0) {
        printf("outer_func: calling inner_func\n");
        inner_func();
    } else {
        printf("outer_func: caught inner jump, jumping to outer\n");
        longjmp(outer, 2);
    }
}

int main(void) {
    int val = setjmp(escape);
    if (val == 0) {
        printf("setjmp returned 0, starting deep calls\n");
        deep_call(5);
        printf("ERROR: deep_call returned normally\n");
    } else {
        printf("longjmp returned %d, depth was %d\n", val, depth);
    }

    int result;
    if (setjmp(error_jmp) == 0) {
        result = safe_divide(100, 5);
        printf("100/5=%d\n", result);
        result = safe_divide(100, 0);
        printf("ERROR: should not reach here\n");
    } else {
        printf("caught divide by zero\n");
    }

    val = setjmp(outer);
    if (val == 0) {
        printf("outer setjmp returned 0\n");
        outer_func();
        printf("ERROR: outer_func returned\n");
    } else {
        printf("outer caught jump with value %d\n", val);
    }

    printf("all setjmp tests passed\n");
    return 0;
}
