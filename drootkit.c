/*
 * @Author: su-cheng
 * @Description: 
 *    This project is designed to detect rootkit attacks in the form 
 *    of kernel modules used to hijack system calls.
 *    This project is implemented by eBPF, there is the user side.
 * @TODO：
 *    1. Receives information from the kernel side.
 *    2. Display alert information on the terminal.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "drootkit.skel.h"
#include "syscall.h"
#include "ht.h"

/* The maximum length of the file /proc/kallsyms line */
#define LINE_MAX 256

/* 
 * The kernel symbol map by parsing the /proc/kallsyms file.
 * each line contains the symbol's address, segment type, name, 
 * module owner (which can be empty in case the symbol is owned by the system).
 */
typedef struct kernel_symbol 
{
	char *name;
	char *type;
	unsigned long long *address;
	char *owner;
} KernelSymbol;

/*
 * Converts the address from string type to ULL
 */
unsigned long long int str_2_addr(char *str, int len) 
{
	unsigned long long int ans = 0;
	for (int i = 0; i < len; ++i) 
	{
		ans = ans * 16;
		if (str[i] <= '9' && str[i] >= '0') 
		{
			ans = ans + (str[i] - '0');
		}
		else 
		{
			ans = ans + (str[i] - 'a' + 10);
		}
	}
	return ans;
}

/* 
 * the kernel_symbol_table holds two mapping tables:
 * 1. symbol_map is used to find symbols by name
 * 2. symbol_addr_map is used to find symbols by address
 */
typedef struct kernel_symbol_table 
{
	ht_item *symbol_map;			//char*, KernelSymbol
	ht_item *symbol_addr_map;		//uint64, KernelSymbol
	bool initialized;
} KernelSymbolTable;

#define MAX_KSYM_NAME_SIZE 64
typedef struct ksym_name 
{
	char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

#define MAX_KSYM_OWNER_SIZE 64
typedef struct ksym_owner 
{
	char str[MAX_KSYM_OWNER_SIZE];
} ksym_owner_t;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) 
{
	return vfprintf(stderr, format, args);
}

struct event {
	unsigned long long int ts;
	int sys_id;
	char sys_name[MAX_KSYM_NAME_SIZE];
	unsigned long long int sys_fake_addr;
	unsigned long long int sys_real_addr;
	char sys_owner[MAX_KSYM_OWNER_SIZE];
};

void get_date(unsigned long long timenum) {
	int nanoseconds = timenum % 1000000000;
	int sec =  timenum / 1000000000;
	int day = (int) (sec / 86400);
	int temp = sec % 86400;
	int hour = (int) (temp / 3600);
	int minute = (int) (temp % 3600 / 60);
	int second = temp % 60;

	double s = second + nanoseconds / 1000000000.0;

	printf("The system call hooking was discovered after the system ran for %d days %dh %dm %.9lfs\n", day, hour, minute, s);
	return ;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char date[32];
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(date, sizeof(date), "%Y-%m-%d", tm);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	
	/* Print a warning message */
	fprintf(stderr, "Now is %s %s\n", date, ts);
	get_date(e->ts);
	fprintf(stderr, "Tampered system call: %d, %s\n", e->sys_id, e->sys_name);
	fprintf(stderr, "fake address: %lld\n", e->sys_fake_addr);
	fprintf(stderr, "real address: %lld\n", e->sys_real_addr);
	fprintf(stderr, "Malicious kernel module: %s\n", e->sys_owner);
	
	/* Recovery system call */
	char cmd[100];
	// sprintf(cmd, "./recovery.sh -i %s", re_syscall.ko);
	// system(cmd);

	/* Uninstalling malicious kernel modules */
	sprintf(cmd, "./recovery.sh -r %s", e->sys_owner);
	system(cmd);

	return 0;
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
	{
		return -errno;
	}

	while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &base) == 4) 
	{
		if (buf[2] == 'x' && (uintptr_t)addr >= start && (uintptr_t)addr < end) 
		{
			found = true;
			break;
		}
	}

	fclose(f);

	if (!found) 
	{
		return -ESRCH;
	}

	return (uintptr_t)addr - start + base;
}

/* It's a global function to make sure compiler doesn't inline it. */
void SyscallsIntergrityCheck() 
{
	printf("Start checking the system call table for rootkit attacks.\n");
}

int main(int argc, char **argv) 
{	
	get_date(760886613318701);
	struct drootkit_bpf *skel;
	long uprobe_offset;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = drootkit_bpf__open_and_load();
	if (!skel) 
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 
	 * The range of symbols required:
	 * 1. sys_call_table
	 * 2. _stext
	 * 3. _etxt
	 * 4. System calls supported by the ARM64 architecture.
	 */
	ht_item *kernel_symbol_needed = NULL;
	
	char *syscall_table_sym = malloc(strlen("sys_call_table") + 1);
	strcpy(syscall_table_sym, "sys_call_table");
	if (!insert_item_over(&kernel_symbol_needed, (void *)syscall_table_sym, strlen(syscall_table_sym), NULL))
	{	
		fprintf(stderr, "Inserting an item into the kernel_symbol_needed failed\n");
		goto cleanup;
	}

	char *start_text_sym = malloc(strlen("_stext") + 1);
	strcpy(start_text_sym, "_stext");
	if (!insert_item_over(&kernel_symbol_needed, (void *)start_text_sym, strlen(start_text_sym), NULL))
	{	
		fprintf(stderr, "Inserting an item into the kernel_symbol_needed failed\n");
		goto cleanup;
	}

	char *end_text_sym = malloc(strlen("_etext") + 1);
	strcpy(end_text_sym, "_etext");
	if (!insert_item_over(&kernel_symbol_needed, (void *)end_text_sym, strlen(end_text_sym), NULL))
	{	
		fprintf(stderr, "Inserting an item into the kernel_symbol_needed failed\n");
		goto cleanup;
	}
	
	for(int i = 0; i < MAX_SYSCALL_ID; ++i) 
	{
		char *need_symbol = malloc(strlen(syscall_64[i]) + 1);
		strcpy(need_symbol, syscall_64[i]);
		if (!insert_item_over(&kernel_symbol_needed, (void *)need_symbol, strlen(need_symbol), NULL))
		{	
			fprintf(stderr, "Inserting an item into the kernel_symbol_needed failed\n");
			goto cleanup;
		}
	}

	/* Create KernelSymbol Table */
	KernelSymbolTable symbol_table;
	symbol_table.symbol_map = NULL;
	symbol_table.symbol_addr_map = NULL;
	symbol_table.initialized = false;

	/* Parse "/proc/kallsyms" and initial KernelSymbolTable */
	char buf[LINE_MAX] = {0};
	char line[4][LINE_MAX] = {0};
	int line_len = 0;
	int line_num = 0;
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f) 
	{
		fprintf(stderr, "could not open /proc/kallsyms\n");
		goto cleanup;
	}

	while (fgets(buf, LINE_MAX, f)) 
	{
		KernelSymbol *symbol = malloc(sizeof(KernelSymbol));
		memset(line, 0, sizeof(line));
		line_len = strlen(buf);
		line_num = 0;

		if ('\n' == buf[line_len - 1]) 
		{
			line_len--;
			if (0 == line_len) 
			{
				continue;
			}
		}

		/* Splits a string, filling KernelSymbol */
		bool is_word;
		for (int i = 0; i <= line_len; ++i) 
		{
			if (buf[i] != ' ' && buf[i] != '\t') 
			{
				is_word = 1;
				line_num++;
			}
			int j = 0;
			while (is_word) 
			{
				line[line_num - 1][j++] = buf[i++];
				if (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n') 
				{
					is_word = 0;
					line[line_num - 1][j] = '\0';
				}
			}
			if (buf[i] == '\n') 
			{
				break;
			}
		}
		if (line_num < 3) 
		{
			continue;
		}
		symbol->address = malloc(sizeof(unsigned long long int));
		*(symbol->address) = str_2_addr(line[0], strlen(line[0]));
		symbol->type = malloc(strlen(line[1]) + 1);
		strcpy(symbol->type, line[1]);
		symbol->name = malloc(strlen(line[2]) + 1);
		strcpy(symbol->name, line[2]);
		if (line_num == 3) 
		{
			symbol->owner = malloc(strlen("[system]") + 1);
			strcpy(symbol->owner, "[system]");
		}
		else 
		{
			symbol->owner = malloc(strlen(line[3]) + 1);
			strcpy(symbol->owner, line[3]);
		}
		
		/*Insert KernelSymbol into symbol_map*/
		if (find_item(&kernel_symbol_needed, (void *)symbol->name, strlen(symbol->name))) 
		{
			if (!insert_item(&symbol_table.symbol_map, (void *)symbol->name, strlen(symbol->name), (void *)symbol))
			{	
				fprintf(stderr, "Inserting an item into the symbol_map failed\n");
				goto cleanup;
			}
			else
			{	
				ht_item *temp = find_item(&symbol_table.symbol_map, (void *)symbol->name, strlen(symbol->name));
				if(temp == NULL) {
					printf("error!\n");
				} else {
					//KernelSymbol *item = (KernelSymbol *)temp->value; 
					//printf("symbol_map: %llx %s %s %s\n", *(item->address), item->type, item->name, item->owner);
				}
			}
		}
		
		/*Insert KernelSymbol into symbol_addr_map*/
		if (strcmp(symbol->owner, "[system]")) {
			if (!insert_item_over(&symbol_table.symbol_addr_map, (void *)symbol->address, sizeof(unsigned long long int), (void *)symbol))
			{	
				fprintf(stderr, "Inserting an item into the symbol_addr_map failed\n");
				goto cleanup;
			}
			else
			{	
				ht_item *temp = find_item(&symbol_table.symbol_addr_map, (void *)symbol->address, sizeof(unsigned long long int));
				if(temp == NULL) {
					printf("error!\n");
				} else {
					//KernelSymbol *item = (KernelSymbol *)temp->value; 
					//printf("symbol_address_map: %llx %s %s %s\n", *(item->address), item->type, item->name, item->owner);
				}
			}
		}
	}
	
	if (0 == feof(f))
	{
		fprintf(stderr, "fgets error: The end of the file was not read\n");
		goto cleanup;
	}
	symbol_table.initialized = true;
	fclose(f);

	/* ksymbols_map initial */
	struct bpf_map *bpf_ksymbols_map;
	bpf_ksymbols_map = bpf_object__find_map_by_name(skel->obj, "ksymbols_map");
	if (!bpf_ksymbols_map)
	{
		err = -errno;
		fprintf(stderr, "Failed to find ksymbols_map: %d\n", err);
		goto cleanup;
	}
	
	ht_item *current_user, *tmp;
	HASH_ITER(hh, symbol_table.symbol_map, current_user, tmp) 
	{
    	ksym_name_t *key = malloc(sizeof(ksym_name_t));
		strcpy(key->str, ((KernelSymbol *)current_user->value)->name);
		unsigned long long int value = *((KernelSymbol *)current_user->value)->address;
		err = bpf_map__update_elem(bpf_ksymbols_map, key, sizeof(ksym_name_t), &value, sizeof(value), BPF_ANY);
		if (err)
		{
			printf("Error: bpf_map_update_elem failed for ksymbols map\n");
			goto cleanup;
		}
	}

	/* address_map initial */
	struct bpf_map *bpf_address_map;
	bpf_address_map = bpf_object__find_map_by_name(skel->obj, "address_map");
	if (!bpf_address_map)
	{
		err = -errno;
		fprintf(stderr, "Failed to find address_map: %d\n", err);
		goto cleanup;
	}
	
	HASH_ITER(hh, symbol_table.symbol_addr_map, current_user, tmp) 
	{
    	unsigned long long int key = *((KernelSymbol *)current_user->value)->address;
		ksym_owner_t *value = malloc(sizeof(ksym_owner_t));
		strcpy(value->str, ((KernelSymbol *)current_user->value)->owner);
		err = bpf_map__update_elem(bpf_address_map, (void*)&key, sizeof(key), value, sizeof(ksym_owner_t), BPF_ANY);
		if (err)
		{
			printf("Error: bpf_map_update_elem failed for address map\n");
			goto cleanup;
		}
	}

	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
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
	if (!skel->links.Syscalls_Intergrity_Check_Entry)
	{
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	// skel->links.Syscalls_Intergrity_Check_Ret = bpf_program__attach_uprobe(skel->progs.Syscalls_Intergrity_Check_Ret,
	// 																	   true /* uretprobe */,
	// 																	   -1 /* any pid */,
	// 																	   "/proc/self/exe",
	// 																	   uprobe_offset);
	// if (!skel->links.Syscalls_Intergrity_Check_Ret)
	// {
	// 	err = -errno;
	// 	fprintf(stderr, "Failed to attach uprobe: %d\n", err);
	// 	goto cleanup;
	// }

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
		   "to see output of the BPF programs.\n");

	for (;;)
	{
		/* trigger our BPF program */
		SyscallsIntergrityCheck();
		sleep(1);
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
	}

cleanup:
	ring_buffer__free(rb);
	drootkit_bpf__destroy(skel);
	return -err;
}
