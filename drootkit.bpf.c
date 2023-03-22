/*
 * @Author: su-cheng
 * @Description: 
 *    This project is designed to detect rootkit attacks in the form 
 *    of kernel modules used to hijack system calls.
 *    This project is implemented by eBPF, there is the kernel side.
 * @TODO：
 *    1. Pass information to the user side.
 *    2. Track the call of a tampered system call, 
 *       to find the process that called it.
 */

#include "vmlinux.h"
#include "syscall.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef unsigned long long u64;

#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif

#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_probe_read((void *) &_val, sizeof(_val), &ptr);                                    \
        _val;                                                                                  \
    })

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
typedef struct ksym_name 
{
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

#define MAX_KSYM_OWNER_SIZE 64
typedef struct ksym_owner 
{
    char str[MAX_KSYM_OWNER_SIZE];
} ksym_owner_t;

BPF_HASH(ksymbols_map, ksym_name_t, u64, 4096);        //we can find symbol address by symbol name through ksymbols_map
BPF_HASH(address_map, u64, ksym_owner_t, 140000);      //we can find symbol owner by symbol address through address_map

typedef struct event {
    u64 ts;
    int sys_id;
    char sys_name[MAX_KSYM_NAME_SIZE];
    u64 sys_fake_addr;
    u64 sys_real_addr;
    char sys_owner[MAX_KSYM_OWNER_SIZE];
} event_t;

struct ringbuf_map{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18 );
} rb SEC(".maps");

static __always_inline void *get_symbol_addr(const char *symbol_name)
{
    char new_ksym_name[MAX_KSYM_NAME_SIZE] = {};
    bpf_probe_read_str(new_ksym_name, MAX_KSYM_NAME_SIZE, symbol_name);
    void **sym = bpf_map_lookup_elem(&ksymbols_map, (void *) &new_ksym_name);

    if (sym == NULL)
        return 0;

    return *sym;
}

static __always_inline void *get_symbol_owner(u64 symbol_address)
{   
    u64 new_ksym_address = symbol_address;
    void **sym = bpf_map_lookup_elem(&address_map, (void *) &new_ksym_address);

    if (sym == NULL)
        return 0;

    return *sym;
}

/*
 * Detects if the system call table has been tampered with:
 * 1. gets the range of addresses for the kernel core text segment, from "_stext" to "_etext".
 * 2. gets the entry address of the system call table.
 * 3. iterate through each item in the system call table（the entry address of the system call，
 *    in turn to see if it belongs to the kernel core text segment.
 *
 *    A brief description of the memory distribution is as follows：
 *    +------------------+------------------------+
 *    |       Owner      |       Description      |
 *    +------------------+------------------------+
 *    |                  |          ....          |
 *    |                  |         .data          |
 *    |      Kernel      |         .init          |
 *    |      Space       |         .text          |
 *    |                  |         modules        |
 *    |                  |          ....          |
 *    +------------------+--  --------------------+
 *    |                  |                        |
 *    |    User Space    |          ....          |
 *    |                  |                        |
 *    +------------------+------------------------+
 *    As you can see, the address ranges of the kernel module and the kernel core text segment
 *    are independent of each other. The original system call entry address is in the kernel 
 *    core text segment, so if the current item does not belong to the kernel core text segment, 
 *    it can be determined to have been tampered with.
 * 4. locate the malicious kernel module that tampers with the system call address and send the 
 *    tampered system call information to the user side.
 */
SEC("uprobe")
int BPF_KPROBE(Syscalls_Intergrity_Check_Entry)
{
    const char start_text_sym[7] = "_stext";
    u64 *stext_addr = (u64 *)get_symbol_addr(start_text_sym);
    if (unlikely(stext_addr == NULL)) {
        return 0;
    }
 
    const char end_text_sym[7] = "_etext";
    u64 *etext_addr = (u64 *)get_symbol_addr(end_text_sym);
    if (unlikely(etext_addr == NULL)){
        return 0;
    }
    
    const char syscall_table_sym[15] = "sys_call_table";
    u64 *syscall_table_addr = (u64 *)get_symbol_addr(syscall_table_sym);
    if (unlikely(syscall_table_addr == NULL)) {
        return 0;
    }

    event_t *e;
    ksym_owner_t *sys_owner;
    for (int i = 0; i < MAX_SYSCALL_ID; i++) {
        u64 syscall_addr = READ_KERN(syscall_table_addr[i]);
        if (syscall_addr == 0) {
            return 0;
        }

        if (syscall_addr >= (u64) stext_addr && syscall_addr < (u64) etext_addr) {
            continue;
        } else {
            e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (!e) {
                return 0;
            }
            /* Locate the malicious kernel module */
            sys_owner = (ksym_owner_t *)get_symbol_owner(syscall_addr);

            /* Collect information about the tampered system call:
             * 1. current timestamp.
             * 2. the id of the system call that was tampered with.
             * 3. the name of the system call that was tampered with.
             * 4. fake system call address.
             * 5. real system call address.
             * 6. the kernel module to which the tampered system call belongs.
             */
            e->ts = bpf_ktime_get_ns();
            e->sys_id = i;
            bpf_probe_read_str(e->sys_name, MAX_KSYM_NAME_SIZE, syscall_64[i]);
            e->sys_fake_addr = syscall_addr;
            bpf_probe_read(&e->sys_real_addr, sizeof(u64), (u64 *)get_symbol_addr(syscall_64[i]));
            bpf_probe_read_str(e->sys_owner, MAX_KSYM_OWNER_SIZE, sys_owner->str);
            
            /*恢复系统调用地址*/

            /* Submit information */       
            bpf_ringbuf_submit(e, 0);
        }
    }
	return 0;
}
