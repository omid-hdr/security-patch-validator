#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    char name[16];
    if (strlen(argv[1]) >= 8) return 2;
    strcpy(name, argv[1]);
    printf("%zu\n", strlen(name));
    return 0;
}
