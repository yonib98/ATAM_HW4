#include "elf64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char *argv[]){
	//char* progname= argv[1];
	char* progname = "a.out";
	FILE* prog = fopen(progname,"r");
	if(prog==NULL){
		printf("couldn't open file\n");
		exit(1);
	}
	Elf64_Ehdr header; 
	fseek(prog, 0, SEEK_SET);
	fread(&header,sizeof(Elf64_Ehdr),1,prog);
	if(header.e_type!=2 && header.e_type!=3){
		printf("PRF:: %s not an executable! :(\n",progname);
		fclose(prog);
		return 0;
	}
	return 0;
	//------------------------PART2-----------------------
}
