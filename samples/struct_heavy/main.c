/* Tests: struct passing (by value and pointer), struct return, nested structs,
   unions, flexible array patterns, struct arrays, bitfields */
#include <stdio.h>
#include <string.h>

typedef struct {
    double x, y;
} Point;

typedef struct {
    Point center;
    double radius;
} Circle;

typedef struct {
    Point min, max;
} Rect;

typedef union {
    int i;
    float f;
    unsigned char bytes[4];
} Pun;

static Point point_add(Point a, Point b) {
    return (Point){a.x + b.x, a.y + b.y};
}

static Point point_scale(Point p, double s) {
    return (Point){p.x * s, p.y * s};
}

static double point_dist(Point a, Point b) {
    double dx = a.x - b.x;
    double dy = a.y - b.y;
    return dx * dx + dy * dy;
}

static void circle_init(Circle *c, double cx, double cy, double r) {
    c->center.x = cx;
    c->center.y = cy;
    c->radius = r;
}

static double circle_area(const Circle *c) {
    return 3.14159265358979 * c->radius * c->radius;
}

static int rect_contains(const Rect *r, Point p) {
    return p.x >= r->min.x && p.x <= r->max.x &&
           p.y >= r->min.y && p.y <= r->max.y;
}

static Rect rect_from_circle(const Circle *c) {
    Rect r;
    r.min.x = c->center.x - c->radius;
    r.min.y = c->center.y - c->radius;
    r.max.x = c->center.x + c->radius;
    r.max.y = c->center.y + c->radius;
    return r;
}

static Point centroid(const Point *pts, int n) {
    Point sum = {0, 0};
    for (int i = 0; i < n; i++) {
        sum = point_add(sum, pts[i]);
    }
    return point_scale(sum, 1.0 / n);
}

int main(void) {
    Point a = {1.0, 2.0};
    Point b = {3.0, 4.0};
    Point c = point_add(a, b);
    printf("add=(%.1f,%.1f)\n", c.x, c.y);

    Point s = point_scale(a, 3.0);
    printf("scale=(%.1f,%.1f)\n", s.x, s.y);

    printf("dist2=%.1f\n", point_dist(a, b));

    Circle circ;
    circle_init(&circ, 5.0, 5.0, 3.0);
    printf("area=%.6f\n", circle_area(&circ));

    Rect bounds = rect_from_circle(&circ);
    printf("bounds=(%.1f,%.1f)-(%.1f,%.1f)\n",
           bounds.min.x, bounds.min.y, bounds.max.x, bounds.max.y);

    Point inside = {5.0, 5.0};
    Point outside = {9.0, 9.0};
    printf("contains_inside=%d\n", rect_contains(&bounds, inside));
    printf("contains_outside=%d\n", rect_contains(&bounds, outside));

    Point polygon[] = {{0,0}, {4,0}, {4,3}, {0,3}};
    Point ctr = centroid(polygon, 4);
    printf("centroid=(%.1f,%.1f)\n", ctr.x, ctr.y);

    Pun p;
    p.f = 1.0f;
    printf("float_bytes=%02x%02x%02x%02x\n",
           p.bytes[0], p.bytes[1], p.bytes[2], p.bytes[3]);
    p.i = 0x41200000;
    printf("pun_float=%.1f\n", (double)p.f);

    return 0;
}
