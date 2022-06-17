#include "elf64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char* argv[]){
    char* progname = "a.out";
	FILE* prog = fopen(progname,"r");
	if(prog==NULL){
		printf("couldn't open file\n");
		exit(1);
	}
    
}
