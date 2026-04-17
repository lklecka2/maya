/* Tests: floating-point arithmetic (exercises SIMD/FP registers),
   math library functions, double/float conversions, FP comparisons */
#include <stdio.h>
#include <math.h>
#include <float.h>

static double dot_product(const double *a, const double *b, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

static double polynomial(double x, const double *coeffs, int degree) {
    double result = coeffs[degree];
    for (int i = degree - 1; i >= 0; i--) {
        result = result * x + coeffs[i];
    }
    return result;
}

static double newton_sqrt(double x) {
    if (x < 0) return -1.0;
    if (x == 0) return 0.0;
    double guess = x / 2.0;
    for (int i = 0; i < 50; i++) {
        guess = (guess + x / guess) / 2.0;
    }
    return guess;
}

static float float_accumulate(const float *arr, int n) {
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

int main(void) {
    double a[] = {1.0, 2.0, 3.0, 4.0, 5.0};
    double b[] = {5.0, 4.0, 3.0, 2.0, 1.0};
    printf("dot=%.1f\n", dot_product(a, b, 5));

    double coeffs[] = {5.0, 1.0, 2.0, 3.0};
    printf("p(0)=%.1f\n", polynomial(0.0, coeffs, 3));
    printf("p(1)=%.1f\n", polynomial(1.0, coeffs, 3));
    printf("p(2)=%.1f\n", polynomial(2.0, coeffs, 3));
    printf("p(10)=%.1f\n", polynomial(10.0, coeffs, 3));

    printf("sqrt(2)=%.10f\n", newton_sqrt(2.0));
    printf("sqrt(144)=%.10f\n", newton_sqrt(144.0));
    printf("sqrt(0)=%.10f\n", newton_sqrt(0.0));

    printf("sin(0)=%.6f\n", sin(0.0));
    printf("sin(pi/2)=%.6f\n", sin(M_PI / 2.0));
    printf("cos(0)=%.6f\n", cos(0.0));
    printf("cos(pi)=%.6f\n", cos(M_PI));
    printf("exp(1)=%.6f\n", exp(1.0));
    printf("log(e)=%.6f\n", log(M_E));

    float farr[] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f, 0.9f, 1.0f};
    printf("fsum=%.1f\n", (double)float_accumulate(farr, 10));

    double zero = 0.0;
    printf("nan==nan:%d\n", (0.0/zero) == (0.0/zero));
    printf("inf>1e308:%d\n", (1.0/zero) > 1e308);

    return 0;
}
