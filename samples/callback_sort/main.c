/* Tests: qsort with comparator callbacks (function pointers passed to libc),
   bsearch, heap allocation (malloc/free), complex data structures */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_int_asc(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

static int cmp_int_desc(const void *a, const void *b) {
    return *(const int *)b - *(const int *)a;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

typedef struct {
    char name[32];
    int score;
} Player;

static int cmp_player_score(const void *a, const void *b) {
    const Player *pa = (const Player *)a;
    const Player *pb = (const Player *)b;
    return pb->score - pa->score;
}

static int cmp_player_name(const void *a, const void *b) {
    const Player *pa = (const Player *)a;
    const Player *pb = (const Player *)b;
    return strcmp(pa->name, pb->name);
}

static void print_ints(const char *label, const int *arr, int n) {
    printf("%s:", label);
    for (int i = 0; i < n; i++) printf(" %d", arr[i]);
    printf("\n");
}

typedef struct Node {
    int value;
    struct Node *next;
} Node;

static Node *list_prepend(Node *head, int val) {
    Node *n = (Node *)malloc(sizeof(Node));
    n->value = val;
    n->next = head;
    return n;
}

static void list_print(const char *label, const Node *head) {
    printf("%s:", label);
    for (const Node *n = head; n; n = n->next)
        printf(" %d", n->value);
    printf("\n");
}

static Node *list_reverse(Node *head) {
    Node *prev = NULL;
    while (head) {
        Node *next = head->next;
        head->next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

static void list_free(Node *head) {
    while (head) {
        Node *next = head->next;
        free(head);
        head = next;
    }
}

int main(void) {
    int nums[] = {42, 17, 99, 3, 28, 55, 7, 81, 13, 64};
    int n = sizeof(nums) / sizeof(nums[0]);

    print_ints("original", nums, n);
    qsort(nums, n, sizeof(int), cmp_int_asc);
    print_ints("asc", nums, n);
    qsort(nums, n, sizeof(int), cmp_int_desc);
    print_ints("desc", nums, n);

    int sorted[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19};
    int key = 7;
    int *found = (int *)bsearch(&key, sorted, 10, sizeof(int), cmp_int_asc);
    printf("bsearch(7)=%s idx=%d\n", found ? "found" : "missing",
           found ? (int)(found - sorted) : -1);
    key = 8;
    found = (int *)bsearch(&key, sorted, 10, sizeof(int), cmp_int_asc);
    printf("bsearch(8)=%s\n", found ? "found" : "missing");

    const char *words[] = {"banana", "apple", "cherry", "date", "elderberry"};
    qsort(words, 5, sizeof(char *), cmp_str);
    printf("sorted:");
    for (int i = 0; i < 5; i++) printf(" %s", words[i]);
    printf("\n");

    Player players[] = {
        {"Alice", 95}, {"Bob", 87}, {"Charlie", 92},
        {"Diana", 98}, {"Eve", 85}
    };
    qsort(players, 5, sizeof(Player), cmp_player_score);
    printf("by_score:");
    for (int i = 0; i < 5; i++)
        printf(" %s(%d)", players[i].name, players[i].score);
    printf("\n");

    qsort(players, 5, sizeof(Player), cmp_player_name);
    printf("by_name:");
    for (int i = 0; i < 5; i++)
        printf(" %s(%d)", players[i].name, players[i].score);
    printf("\n");

    Node *list = NULL;
    for (int i = 0; i < 8; i++)
        list = list_prepend(list, i * 10);
    list_print("list", list);

    list = list_reverse(list);
    list_print("reversed", list);

    list_free(list);
    printf("freed\n");

    return 0;
}
