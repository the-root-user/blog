#include <stdio.h>

void print_user_data(char* arg1, char* arg2, char* arg3){
    printf("Here is Your data\n");
    printf("Name: %s  Age: %s  Job: %s\n", arg1, arg2, arg3);
}

void main(int argc, char **argv){
    if (argc!=4){
        printf("Please provide 3 inputs\n");
    }
    else {
        print_user_data(argv[1], argv[2], argv[3]);
    }
}
