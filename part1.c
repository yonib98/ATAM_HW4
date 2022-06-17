#include "elf64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
int main(int argc,char *argv[]){
	//char* progname= argv[1];
	//char* func_to_debug = argv[2];
	char* progname = "test.out";
	char* func_to_debug = "foo";
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
	//------------------------PART2-----------------------
	fseek(prog,header.e_shoff,SEEK_SET); //Start of section headers table
	int sh_size = header.e_shentsize;
	int sh_count = header.e_shnum;

	Elf64_Shdr* sh_arr = malloc(sizeof(Elf64_Shdr)*sh_count);
	if(sh_arr==NULL){
		exit(1);
	}
	fread(sh_arr,sh_size,sh_count,prog);


	Elf64_Shdr sh_symtab;
	Elf64_Shdr sh_strtab;
	for(int i=0;i<sh_count;i++){
		if(sh_arr[i].sh_type==0x2){
			sh_symtab=sh_arr[i];
		}
		if(sh_arr[i].sh_type==0x3 && i!=header.e_shstrndx){
			sh_strtab=sh_arr[i];
		}
	}
	fseek(prog,sh_strtab.sh_offset,SEEK_SET);
	char * strtab_dump = malloc(sizeof(char)*sh_strtab.sh_size);
	fread(strtab_dump,sh_strtab.sh_size,1,prog);

	fseek(prog,sh_symtab.sh_offset,SEEK_SET);
	int sym_count = sh_symtab.sh_size/sh_symtab.sh_entsize;
	Elf64_Sym* symtab_entries = malloc(sizeof(Elf64_Sym)*sym_count);
	if(symtab_entries==NULL){
		exit(1);
	}
	fread(symtab_entries,sh_symtab.sh_entsize,sym_count,prog);
	bool found_function=false;
	for(int i=0;i<sym_count;i++){
		if(i==51){
			printf("hey");
		}
		int strtab_index = symtab_entries[i].st_name;
		char* sym_name = &strtab_dump[strtab_index];
		if(strcmp(sym_name,func_to_debug)==0){
			found_function =true;
			break;
		}
	}
	if(!found_function){
		printf("PRF:: %s not found!\n", func_to_debug);
	}


}
