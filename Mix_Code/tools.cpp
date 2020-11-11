#include <stdio.h>
#include <stdlib.h>

// OpenFile more safe
FILE* OpenFile(char* fileinput) {
    FILE* file;
    if ((file = fopen(fileinput, "r+")) == NULL) {
        printf("%s\n", "File Open Error!");
        exit(0);
    }
    return file;
}

// Tell file frame position
long int ftellSafe(FILE* file) {
    long int pos;
    if ((pos = ftell(file)) == -1L) {
        exit(0);
    }
    return pos;
}
