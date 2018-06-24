#include <stdio.h>

int func(int x, int y)
{
    int a = x;
    int b = y;
    int c = 0xface;
    int d = 0xb00c;
    int e = c + d;
    return a ^ b;
}

int main(void)
{
    int x, y;
    printf("x: ");
    scanf("%d", &x);
    printf("y: ");
    scanf("%d", &y);
    printf("result: %d\n", func(x, y));
    return 0;
}
