// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "drootkit.skel.h"
#include "ht.h"
#viminclude "syscall.h"

/* The maximum length of the file /proc/kallsyms line */
#define LINE_MAX 256

/* the kernel symbol map by parsing the /proc/kallsyms file.
 * each line contains the symbol's address, segment type, name, module owner (which can be empty in case the symbol is owned by the system)
 */
typedef struct kernel_symbol{
	char *name;
	char *type;
	unsigned long long address;
	char *owner;
}KernelSymbol;

unsigned long long int str_2_addr(char * str, int len) {
	unsigned long long int ans = 0;
	for (int i = 0; i < len; ++i) {
		ans = ans *10 + (str[i] - '0');
	}
	return ans;
}

/* the kernel_symbol_table holds two mapping tables:
 * 1. symbol_map is used to find symbols by name
 * 2. symbol_addr_map is used to find symbols by address
 */
typedef struct kernel_symbol_table{
	ht *symbol_map;     			//char*, KernelSymbol
	ht *symbol_addr_map; 			//uint64, KernelSymbol
	bool initialized;
}KernelSymbolTable;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/*
 * Taken from https://github.com/torvalds/linux/blob/9b59ec8d50a1f28747ceff9a4f39af5deba9540e/tools/testing/selftests/bpf/trace_helpers.c#L149-L205
 *
 * See discussion in https://github.com/libbpf/libbpf-bootstrap/pull/90
 */
ssize_t get_uprobe_offset(const void *addr)
{
	size_t start, end, base;
	char buf[256];
	bool found = false;
	FILE *f;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &base) == 4) {
		if (buf[2] == 'x' && (uintptr_t)addr >= start && (uintptr_t)addr < end) {
			found = true;
			break;
		}
	}

	fclose(f);

	if (!found)
		return -ESRCH;

	return (uintptr_t)addr - start + base;
}

/* It's a global function to make sure compiler doesn't inline it. */
void SyscallsIntergrityCheck()
{
	printf("Start checking the system call table for rootkit attacks.\n");
}

int main(int argc, char **argv)
{
	struct drootkit_bpf *skel;
	long uprobe_offset;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = drootkit_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    /* ksymbols_map initial */
    struct bpf_map *bpf_ksymbols_map;
    bpf_ksymbols_map = bpf_object__find_map_by_name(skel->obj, "ksymbols_map");
    if (!bpf_ksymbols_map) {
		err = -errno;
		fprintf(stderr, "Failed to find ksymbols_map: %d\n", err);
		goto cleanup;
	}
	/* 限定需要放入hash表的符号范围 */

	/* 创建两个hash表*/
	KernelSymbolTable symbol_table;
	symbol_table.symbol_map = ht_create();
	//symbol_table.symbol_addr_map = ht_create();
	symbol_table.initialized = false;

	char buf[LINE_MAX] = {0};
	char line[4][LINE_MAX] = {0};
	int line_len = 0;
	int line_num = 0;
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f) {
		fprintf(stderr, "could not open /proc/kallsyms\n");
		goto cleanup;
	}
	int line_pnum = 0 ,insert_num = 0;
	while (fgets(buf, LINE_MAX, f)) {
		KernelSymbol symbol = {};
		memset(line, 0, sizeof(line));
		line_len = strlen(buf);
		line_num = 0;
		line_pnum++;

		if ('\n' == buf[line_len - 1]) {
			line_len--;
			if (0 == line_len) {
				continue;
			}
		}
		
		/* Splits a string, filling KernelSymbol */
		bool is_word;
		for (int i = 0; i <= line_len; ++i) {
			if (buf[i] != ' ' && buf[i] != '\t') {
				is_word = 1;
				line_num++;
			}
			int j = 0;
			while (is_word) {
				line[line_num - 1][j++] = buf[i++];
				if (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n') {
					is_word = 0;
					line[line_num - 1][j] = '\0';
				}
			}
			if (buf[i] == '\n') {
				break;
			}
		}
		if (line_num < 3) {
			continue;
		}
		symbol.address = str_2_addr(line[0], strlen(line[0]));
		symbol.type = line[1];
		symbol.name = line[2];
		if (line_num == 3) {
			symbol.owner = "[system]";
		} else {
			symbol.owner = line[3];
		}

		FILE *tf = fopen("./1.txt", "a");
		fprintf(tf, "%llu %s %s %s\n", symbol.address, symbol.type, symbol.name, symbol.owner);
		fclose(tf);

		/*Insert KernelSymbol into symbol_map*/
		if (ht_set(symbol_table.symbol_map, symbol.name, (void*)&symbol) == NULL)
        {
            fprintf(stderr, "out of memory\n");
			goto cleanup;
        } else {
			insert_num++;
		}
		/*Insert KernelSymbol into symbol_addr_map*/
	}
	FILE *ttf = fopen("./2.txt", "a");
	hti it = ht_iterator(symbol_table.symbol_map);
	while (ht_next(&it))
	{	
		//fprintf(ttf, "%d %s:", it._index, it.key);
		fprintf(ttf, "%llu %s %s %s\n", ((KernelSymbol*)it.value)->address, ((KernelSymbol*)it.value)->type, ((KernelSymbol*)it.value)->name, ((KernelSymbol*)it.value)->owner);
	}
	fclose(ttf);
	printf("insert_num=%d line_allnum=%d ht_lenght=%lu\n", insert_num, line_pnum, ht_length(symbol_table.symbol_map));
	
	if (0 == feof(f)) {
		fprintf(stderr, "fgets error: The end of the file was not read\n");	
		goto cleanup;
	}
	symbol_table.initialized = true;
	fclose(f);	

	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. This offset is relateve to the process's base load address. So
	 * easy way to do this is to take an absolute address of the desired
	 * function and substract base load address from it.  If we were to
	 * parse ELF to calculate this function, we'd need to add .text
	 * section offset and function's offset within .text ELF section.
	 */
	uprobe_offset = get_uprobe_offset(&SyscallsIntergrityCheck);

	/* Attach tracepoint handler */
	skel->links.Syscalls_Intergrity_Check_Entry = bpf_program__attach_uprobe(skel->progs.Syscalls_Intergrity_Check_Entry,
							    false /* not uretprobe */,
							    0 /* self pid */,
							    "/proc/self/exe",
							    uprobe_offset);
	if (!skel->links.Syscalls_Intergrity_Check_Entry) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	skel->links.Syscalls_Intergrity_Check_Ret = bpf_program__attach_uprobe(skel->progs.Syscalls_Intergrity_Check_Ret,
							       true /* uretprobe */,
							       -1 /* any pid */,
							       "/proc/self/exe",
							       uprobe_offset);
	if (!skel->links.Syscalls_Intergrity_Check_Ret) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

    for (;;) {
            /* trigger our BPF program */
            SyscallsIntergrityCheck();
            sleep(1);
        }

cleanup:
	drootkit_bpf__destroy(skel);
	return -err;
}
