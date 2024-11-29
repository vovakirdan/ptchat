// test vector
#include <stdio.h>
#include "cbinc/print.h"
#include "cbinc/vector.h"

void show(struct vector(int) v)
{
    for (var it = vector__begin(int, v); it < vector__end(int, v); ++it)
        print((double) *it, (char) ' ');
    printn((char) '\n');
}

int main() {
    struct vector(int) v = {};
    vector__reserve_exact(int, 10, v);
    for (int i = 0; i < 40; i++) vector__push_back(int, 1, v);
    int* second = vector__access(int, 32, v);
    printf("%d\n", *second);
    show(v);
    vector__delete(int, v.data, v.size, NULL, v);
    show(v);
    for (int i = 0; i < 4; i++) vector__push_back(int, i, v);
    int *p = 10;
    struct slice(int) s = slice__create(int, &p, 1);
    vector__insert(int, (char *)v.data + sizeof(int), s, v);
    show(v);

    vector__destroy(int, NULL, v);
}