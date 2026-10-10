#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned int random = rand(); // Default seed (no srand)
    printf("Random: %u\n", random);
    return 0;
}