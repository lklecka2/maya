/* Tests: string manipulation, memcpy/memset/memmove, buffer operations,
   manual string functions (exercises byte-level loads/stores) */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int my_strlen(const char *s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

static void my_reverse(char *s) {
    int len = my_strlen(s);
    for (int i = 0; i < len / 2; i++) {
        char tmp = s[i];
        s[i] = s[len - 1 - i];
        s[len - 1 - i] = tmp;
    }
}

static int my_strcmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void to_upper(char *dst, const char *src) {
    while (*src) {
        *dst++ = (char)toupper((unsigned char)*src++);
    }
    *dst = '\0';
}

static int count_char(const char *s, char c) {
    int count = 0;
    for (int i = 0; s[i]; i++) {
        if (s[i] == c) count++;
    }
    return count;
}

static int is_palindrome(const char *s) {
    int len = my_strlen(s);
    for (int i = 0; i < len / 2; i++) {
        if (s[i] != s[len - 1 - i]) return 0;
    }
    return 1;
}

static void rot13(char *dst, const char *src) {
    while (*src) {
        char c = *src;
        if (c >= 'a' && c <= 'z')
            c = 'a' + (c - 'a' + 13) % 26;
        else if (c >= 'A' && c <= 'Z')
            c = 'A' + (c - 'A' + 13) % 26;
        *dst++ = c;
        src++;
    }
    *dst = '\0';
}

static void itoa_simple(int n, char *buf) {
    int neg = 0;
    if (n < 0) { neg = 1; n = -n; }
    int i = 0;
    do {
        buf[i++] = '0' + (n % 10);
        n /= 10;
    } while (n > 0);
    if (neg) buf[i++] = '-';
    buf[i] = '\0';
    my_reverse(buf);
}

int main(void) {
    printf("len(hello)=%d\n", my_strlen("hello"));
    printf("len()=%d\n", my_strlen(""));

    char buf[64];
    strcpy(buf, "abcdefgh");
    my_reverse(buf);
    printf("reverse=%s\n", buf);

    printf("cmp(abc,abd)=%d\n", my_strcmp("abc", "abd") < 0 ? -1 : 1);
    printf("cmp(abc,abc)=%d\n", my_strcmp("abc", "abc"));

    to_upper(buf, "Hello World!");
    printf("upper=%s\n", buf);

    printf("count(mississippi,s)=%d\n", count_char("mississippi", 's'));
    printf("count(mississippi,i)=%d\n", count_char("mississippi", 'i'));

    printf("palindrome(racecar)=%d\n", is_palindrome("racecar"));
    printf("palindrome(hello)=%d\n", is_palindrome("hello"));
    printf("palindrome(a)=%d\n", is_palindrome("a"));

    rot13(buf, "Hello World");
    printf("rot13=%s\n", buf);
    rot13(buf, buf);
    printf("rot13x2=%s\n", buf);

    char numbuf[32];
    itoa_simple(12345, numbuf);
    printf("itoa(12345)=%s\n", numbuf);
    itoa_simple(-42, numbuf);
    printf("itoa(-42)=%s\n", numbuf);
    itoa_simple(0, numbuf);
    printf("itoa(0)=%s\n", numbuf);

    char a[32], b[32];
    memset(a, 'X', 16);
    a[16] = '\0';
    printf("memset=%s\n", a);
    memcpy(b, a, 17);
    printf("memcpy=%s\n", b);

    char overlap[] = "0123456789";
    memmove(overlap + 2, overlap, 6);
    overlap[10] = '\0';
    printf("memmove=%s\n", overlap);

    return 0;
}
