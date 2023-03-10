// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
//#include <linux/bpf.h>
//#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                                      \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define MAX_KSYM_NAME_SIZE 64

typedef unsigned long long u64;
typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

BPF_HASH(ksymbols_map, ksym_name_t, u64, 4096);                    // holds the addresses of some kernel symbols

static __always_inline void *get_symbol_addr(char *symbol_name)
{
    char new_ksym_name[MAX_KSYM_NAME_SIZE] = {};
    bpf_probe_read_str(new_ksym_name, MAX_KSYM_NAME_SIZE, symbol_name);
    void **sym = bpf_map_lookup_elem(&ksymbols_map, (void *) &new_ksym_name);

    if (sym == NULL)
        return 0;

    return *sym;
}

SEC("uprobe")
int BPF_KPROBE(Syscalls_Intergrity_Check_Entry)
{
	bpf_printk("SyscallsIntergrityCheck ENTRY");

    // char syscall_table_sym[15] = "sys_call_table";
    // u64 *syscall_table_addr = (u64 *) get_symbol_addr(syscall_table_sym);
    // if (unlikely(syscall_table_addr == 0)) {
    //     return 0;
    // }

    // char start_text_sym[7] = "_stext";
    // void *stext_addr = get_symbol_addr(start_text_sym);
    // if (unlikely(stext_addr == NULL)) {
    //     return 0;
    // }

    // char end_text_sym[7] = "_etext";
    // void *etext_addr = get_symbol_addr(end_text_sym);
    // if (unlikely(etext_addr == NULL)){
    //     return 0;
    // }
    
    // u64 idx;
    // unsigned long syscall_addr = 0;
    // u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK];

    // for (int i = 0; i < NUMBER_OF_SYSCALLS_TO_CHECK; i++) {
    //     idx = i;
    //     // syscalls_to_check_map format: [syscall#][syscall#][syscall#]
    //     u64 *syscall_num_p = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &idx);
    //     if (syscall_num_p == NULL) {
    //         syscall_address[i] = 0;
    //         continue;
    //     }

    //     syscall_addr = READ_KERN(syscall_table_addr[*syscall_num_p]);
    //     if (syscall_addr == 0) {
    //         return 0;
    //     }

    //     // skip if in text segment range
    //     if (syscall_addr >= (u64) stext_addr && syscall_addr < (u64) etext_addr) {
    //         syscall_address[i] = 0;
    //         continue;
    //     }

    //     syscall_address[i] = syscall_addr;
    // }

	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(Syscalls_Intergrity_Check_Ret, int ret)
{
	bpf_printk("SyscallsIntergrityCheck RETURN");
	return 0;
}

