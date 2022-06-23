#include "elf64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/user.h>
int main(int argc, char *argv[])
{
	 char* func_to_debug = argv[1];
	char* progname= argv[2];

//	char *progname = "dynamic.out";
//	char *func_to_debug = "foo";
	FILE *prog = fopen(progname, "r");
	if (prog == NULL)
	{
		printf("couldn't open file\n");
		exit(1);
	}
	Elf64_Ehdr header;
	fseek(prog, 0, SEEK_SET);
	fread(&header, sizeof(Elf64_Ehdr), 1, prog);
	if (header.e_type != 2)
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
	Elf64_Shdr sh_shstrtab = sh_arr[header.e_shstrndx];

	fseek(prog, sh_shstrtab.sh_offset, SEEK_SET);
	char *sh_strtab_dump = malloc(sizeof(char) * sh_shstrtab.sh_size);
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
		return 0;
	}
	//----------------------------PART3------------------------//
	int bind = ELF64_ST_BIND(func_symbol.st_info);
	if (bind != 1)
	{
		// BE SURE ITS CORRECT
		printf("PRF:: %s is not a global symbol! :(\n", func_to_debug);
		return 0;
	}
	//----------------------------PART4------------------------//
	unsigned long func_address;
	bool is_defined = func_symbol.st_shndx;
	if (!is_defined)
	{
		// Part5
		fseek(prog, sh_rela.sh_offset, SEEK_SET);
		int rela_count = sh_rela.sh_size / sh_rela.sh_entsize;
		Elf64_Rela *rela_entries = malloc(sizeof(Elf64_Rela) * rela_count);
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
				func_address = rela_entries[i].r_offset;
				break;
			}
		}
	}
	else
	{
		func_address = func_symbol.st_value;
	}
	//-------------------------------PART6-------------------------//
	pid_t child = run_target(progname,argv+2);
	if (!is_defined)
	{
		run_dynamic_breakpoint(child, func_address);
	}
	else
	{
		run_breakpoint_debugger(child, func_address, 0);
	}
}

pid_t run_target(const char *programname,char** child_argv)
{
	pid_t pid;
	pid = fork();
	if (pid > 0)
	{
		return pid;
	}
	else if (pid == 0)
	{
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
		{
			perror("ptrace");
			exit(1);
		}
		execv(programname,child_argv);
	}
	else
	{
		perror("fork");
		exit(1);
	}
}
void debug_func(pid_t child_pid, unsigned long func_address, int iterations_counter)
{
	struct user_regs_struct regs;
	int wait_status;
	unsigned long func_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)func_address, NULL);
	unsigned long func_data_trap = (func_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
	ptrace(PTRACE_POKETEXT, child_pid, (void *)func_address, (void *)func_data_trap);
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	wait(&wait_status);

	while (!WIFEXITED(wait_status))
	{
		// deleting the CC from the beginning of the function
		iterations_counter++;
		ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
		ptrace(PTRACE_POKETEXT, child_pid, (void *)func_address, (void *)func_data);
		regs.rip -= 1;
		ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

		// breakpoint after returning from function
		long top_of_stack = regs.rsp;
		unsigned long return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)top_of_stack, NULL);
		long return_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)return_address, NULL);
		long return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
		ptrace(PTRACE_POKETEXT, child_pid, (void *)return_address, (void *)return_data_trap);
		ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		wait(&wait_status);

		// printing
		ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
		printf("PRF:: run #%lld returned with %d\n", iterations_counter, regs.rax);

		// delete breakpoint: return from function
		ptrace(PTRACE_POKETEXT, child_pid, (void *)return_address, (void *)return_data);
		regs.rip -= 1;
		ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

		// restore the breakpoint to the entry of the function.
		ptrace(PTRACE_POKETEXT, child_pid, (void *)func_address, (void *)func_data_trap);
		ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		wait(&wait_status);
	}
}

void run_breakpoint_debugger(pid_t child_pid, unsigned long func_address)
{
	int wait_status;
	wait(&wait_status);
	debug_func(child_pid, func_address, 0);
}

void run_dynamic_breakpoint(pid_t child_pid, unsigned long plt_address)
{
	int iterations_counter = 0;
	int wait_status;
	struct user_regs_struct regs;
	wait(&wait_status);
	unsigned long func_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)plt_address, NULL);
	long func_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)func_address, NULL);

	long func_data_trap = (func_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
	ptrace(PTRACE_POKETEXT, child_pid, (void *)func_address, (void *)func_data_trap);
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	wait(&wait_status);
	if (WIFEXITED(wait_status))
	{
		return;
	}
	// deleting the CC from the beginning of the function
	iterations_counter++;
	ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
	ptrace(PTRACE_POKETEXT, child_pid, (void *)func_address, (void *)func_data);
	regs.rip -= 1;
	ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

	// breakpoint after returning from function
	long top_of_stack = regs.rsp;
	unsigned long return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)top_of_stack, NULL);
	long return_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)return_address, NULL);
	long return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;

	ptrace(PTRACE_POKETEXT, child_pid, (void *)return_address, (void *)return_data_trap);
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	wait(&wait_status);

	ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
	printf("PRF:: run #%lld returned with %d\n", iterations_counter, regs.rax);

	// delete breakpoint: return from function
	ptrace(PTRACE_POKETEXT, child_pid, (void *)return_address, (void *)return_data);
	regs.rip -= 1;
	ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

	func_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)plt_address, NULL);
	debug_func(child_pid, func_address, iterations_counter);
}