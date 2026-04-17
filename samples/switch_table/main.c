/* Tests: large switch statements (may generate jump tables in .rodata),
   dense and sparse switch, nested switch, enum-based dispatch */
#include <stdio.h>

static const char *day_name(int d) {
    switch (d) {
    case 0: return "Sunday";
    case 1: return "Monday";
    case 2: return "Tuesday";
    case 3: return "Wednesday";
    case 4: return "Thursday";
    case 5: return "Friday";
    case 6: return "Saturday";
    default: return "Unknown";
    }
}

static int score_char(char c) {
    switch (c) {
    case 'a': case 'e': case 'i': case 'l': case 'n':
    case 'o': case 'r': case 's': case 't': case 'u':
        return 1;
    case 'd': case 'g':
        return 2;
    case 'b': case 'c': case 'm': case 'p':
        return 3;
    case 'f': case 'h': case 'v': case 'w': case 'y':
        return 4;
    case 'k':
        return 5;
    case 'j': case 'x':
        return 8;
    case 'q': case 'z':
        return 10;
    default:
        return 0;
    }
}

static int scrabble_score(const char *word) {
    int total = 0;
    for (int i = 0; word[i]; i++) {
        total += score_char(word[i]);
    }
    return total;
}

static const char *http_status(int code) {
    switch (code) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
    }
}

static const char *classify(int category, int sub) {
    switch (category) {
    case 1:
        switch (sub) {
        case 0: return "1a";
        case 1: return "1b";
        case 2: return "1c";
        default: return "1?";
        }
    case 2:
        switch (sub) {
        case 0: return "2a";
        case 1: return "2b";
        default: return "2?";
        }
    case 3: return "3x";
    default: return "??";
    }
}

int main(void) {
    for (int d = 0; d <= 7; d++) {
        printf("day(%d)=%s\n", d, day_name(d));
    }

    const char *words[] = {"hello", "quartz", "jazz", "xylophone", "rhythm"};
    for (int i = 0; i < 5; i++) {
        printf("scrabble(\"%s\")=%d\n", words[i], scrabble_score(words[i]));
    }

    int codes[] = {200, 201, 301, 404, 500, 999};
    for (int i = 0; i < 6; i++) {
        printf("http(%d)=%s\n", codes[i], http_status(codes[i]));
    }

    for (int c = 1; c <= 3; c++) {
        for (int s = 0; s <= 2; s++) {
            printf("classify(%d,%d)=%s\n", c, s, classify(c, s));
        }
    }

    return 0;
}
