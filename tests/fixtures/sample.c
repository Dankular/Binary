#include <stdio.h>

int add(int a, int b) { return a + b; }

int main(int argc, char** argv) {
    int x = add(3, 4);
    if (x > 5) {
        printf("big %d\n", x);
    } else {
        printf("small\n");
    }
    return 0;
}
