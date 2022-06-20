#include "elf64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
int main(int argc, char *argv[])
{
	// char* progname= argv[1];
	// char* func_to_debug = argv[2];
	char *progname = "test2.out";
	char *func_to_debug = "foo";
	FILE *prog = fopen(progname, "r");
	if (prog == NULL)
	{
		printf("couldn't open file\n");
		exit(1);
	}
	Elf64_Ehdr header;
	fseek(prog, 0, SEEK_SET);
	fread(&header, sizeof(Elf64_Ehdr), 1, prog);
	if (header.e_type != 2 && header.e_type != 3)
	{
		printf("PRF:: %s not an executable! :(\n", progname);
		fclose(prog);
		return 0;
	}
	//------------------------PART2-----------------------
	fseek(prog, header.e_shoff, SEEK_SET); // Start of section headers table
	int sh_size = header.e_shentsize;
	int sh_count = header.e_shnum;

	Elf64_Shdr *sh_arr = malloc(sizeof(Elf64_Shdr) * sh_count);
	if (sh_arr == NULL)
	{
		exit(1);
	}
	fread(sh_arr, sh_size, sh_count, prog);
	Elf64_Shdr sh_shstrtab=sh_arr[header.e_shstrndx];

	fseek(prog, sh_shstrtab.sh_offset, SEEK_SET);
	char* sh_strtab_dump=malloc(sizeof(char)* sh_shstrtab.sh_size);
    fread(sh_strtab_dump, sh_shstrtab.sh_size, 1, prog);

	Elf64_Shdr sh_symtab;
	Elf64_Shdr sh_strtab;
	Elf64_Shdr sh_rela;
	Elf64_Shdr sh_dynsym;
	Elf64_Shdr sh_dynstr;
	for (int i = 0; i < sh_count; i++)
	{
		int sh_strtab_index = sh_arr[i].sh_name;
		char *section_name = &sh_strtab_dump[sh_strtab_index];
		if (strcmp(".rela.plt", section_name) == 0)
		{
				sh_rela = sh_arr[i];
		}
		else if (strcmp(".dynsym", section_name) == 0)
		{
				sh_dynsym = sh_arr[i];
		}
		else if (strcmp(".dynstr", section_name) == 0)
		{
			sh_dynstr = sh_arr[i];
		}
		else if (strcmp(".symtab", section_name) == 0)
		{
			sh_symtab = sh_arr[i];
		}
		else if (strcmp(".strtab", section_name) == 0)
		{
			sh_strtab = sh_arr[i];
		}
		
	}
	fseek(prog, sh_strtab.sh_offset, SEEK_SET);
	char *strtab_dump = malloc(sizeof(char) * sh_strtab.sh_size);
	fread(strtab_dump, sh_strtab.sh_size, 1, prog);


	fseek(prog, sh_symtab.sh_offset, SEEK_SET);
	int sym_count = sh_symtab.sh_size / sh_symtab.sh_entsize;
	Elf64_Sym *symtab_entries = malloc(sizeof(Elf64_Sym) * sym_count);
	if (symtab_entries == NULL)
	{
		exit(1);
	}
	fread(symtab_entries, sh_symtab.sh_entsize, sym_count, prog);
	bool found_function = false;
	Elf64_Sym func_symbol;
	for (int i = 0; i < sym_count; i++)
	{
		int strtab_index = symtab_entries[i].st_name;
		char *sym_name = &strtab_dump[strtab_index];
		if (strcmp(sym_name, func_to_debug) == 0)
		{
			func_symbol = symtab_entries[i];
			found_function = true;
			break;
		}
	}
	if (!found_function)
	{
		printf("PRF:: %s not found!\n", func_to_debug);
	}
	//----------------------------PART3------------------------//
	int bind = ELF64_ST_BIND(func_symbol.st_info);
	if (bind != 1)
	{
		// BE SURE ITS CORRECT
		printf("PRF:: %s is not a global symbol! :(\n", func_to_debug);
	}
	//----------------------------PART4------------------------//
	Elf64_Addr func_address;
	bool is_defined = func_symbol.st_shndx;
	if (!is_defined)
	{
		// Part5
		fseek(prog, sh_rela.sh_offset, SEEK_SET);
		int rela_count = sh_rela.sh_size / sh_rela.sh_entsize;
		Elf64_Rel *rela_entries = malloc(sizeof(Elf64_Rel) * rela_count);
		if (rela_entries == NULL)
		{
			exit(1);
		}
		fread(rela_entries, sh_rela.sh_entsize, rela_count, prog);

		fseek(prog, sh_dynsym.sh_offset, SEEK_SET);
		int dynsym_count = sh_dynsym.sh_size / sh_dynsym.sh_entsize;
		Elf64_Sym *dynsym_entries = malloc(sizeof(Elf64_Sym) * dynsym_count);
		if (dynsym_entries == NULL)
		{
			exit(1);
		}
		fread(dynsym_entries, sh_dynsym.sh_entsize, dynsym_count, prog);



		fseek(prog, sh_dynstr.sh_offset, SEEK_SET);
		char *dynstr_dump = malloc(sizeof(char) * sh_dynstr.sh_size);
		fread(dynstr_dump, sh_dynstr.sh_size, 1, prog);
		for (int i = 0; i < rela_count; i++)
		{
			int dynsym_index = ELF64_R_SYM(rela_entries[i].r_info);
			int strtab_index = dynsym_entries[dynsym_index].st_name;
			char *sym_name = &dynstr_dump[strtab_index];
			if (strcmp(sym_name, func_to_debug) == 0)
			{
				func_address= rela_entries[i].r_offset;
				break;
			}
		}
	}
	else{
		func_address=func_symbol.st_value;
	}
	printf("function adress is : %p\n", func_address);
	//-------------------------------PART6-------------------------//
}
