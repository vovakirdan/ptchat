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
    vector__push_back(int, 1, v);
    vector__push_back(int, 2, v);
    int* second = vector__access(int, 1, v);
    printf("%d\n", *second);
    show(v);
}