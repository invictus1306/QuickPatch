#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASSWORD "patch_me"
#define SIZE 256

int main(void) {
    char buffer[SIZE];

    printf("Password: ");

    fgets(buffer, SIZE, stdin);

    if (strncmp(buffer, PASSWORD, strlen(buffer)-1) == 0) {
        printf("Password correct!\n");
        return 0;
    }
    printf("Password incorrect!\n");
    
    return 0;
}
