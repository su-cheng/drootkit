// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "drootkit.skel.h"
#include "String.h"

/* 
 * the implement of type String 
 */
bool StrAssign(String *S, char **chars) {
	if(S->ch) {
		S->length = 0;
		free(S->ch);
		S->ch = NULL;
	}
    
	int i;
	char *c;

	for(i = 0, c = *chars; *c; i++, c++);
	if (!i) {
		S->ch = NULL;
		S->length = 0;
	}
	else {
		S->ch = (char*)malloc(i * sizeof(char));
		for(int j = 0; j < i; j++) {
			S->ch[j] = (*chars)[j];
		}
		S->length = i;
	}
	return OK;
}

unsigned int Length(String S) {
	return S.length;
}

/*compare S1 and S2 and if S1 > S2 return 1 else return 0*/
bool Compare(String S1, String S2) {
	int i, j;
	for (i = 0, j = 0; i < S1.length || i < S2.length; i++, j++) {
		if (S1.ch[i] > S2.ch[j]) {
			return 1;
		}
		else if (S1.ch[i] < S2.ch[j]) {
			return 0;
		}
		else {
			continue;
		}
	}
	if(S1.length > S2.length) 
		return 1;
	else
		return 0;
}

/*empty the string*/
void ClearString(String *S) {
	S->length = 0;
	free(S->ch);
	S->ch = NULL;
}

/*concat S1 and S2 and return the value using T*/
bool Concat(String *S, String S1, String S2) {
	S->ch = (char*)malloc((S1.length + S2.length) * sizeof(char));
	S->length = S1.length + S2.length;
	for (int i = 0; i < S1.length; i++) {
		S->ch[i] = S1.ch[i];
	}
	for (int i = 0; i < S2.length; i++) {
		S->ch[i + S1.length] = S2.ch[i];
	}
	return OK;	
}

/*return a substring of S whose length is len from the position of pos*/
String SubString(String S, int pos, int len) {
	String T;
	T.length = len;
	T.ch = (char*)malloc(len*sizeof(char));
	for (int i = pos - 1; i < pos - 1 + len; i++) {
		T.ch[i - pos + 1] = S.ch[i];
	}
	return T;
}

void Traverse(String S) {
	if (S.ch == NULL)
		printf("null");
	else {
		for (int i = 0; i < S.length; i++) {
			printf("%c", S.ch[i]);
		}
	}
	printf("\n");
} 

/* the kernel symbol map by parsing the /proc/kallsyms file.
 * each line contains the symbol's address, segment type, name, module owner (which can be empty in case the symbol is owned by the system)
 */
typedef struct kernel_symbol{
	char name[64];
	char type[2];
	unsigned long long address;
	char owner[64];
}KernelSymbol;

// typedef struct kernel_symbol_table{
// 	symbolMap     map[string]KernelSymbol
// 	symbolAddrMap map[uint64]KernelSymbol
// 	bool initialized;
// }KernelSymbolTable;

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