// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "tracee.skel.h"
#include "event.h"

enum bpf_config_option_value{
	UNDEFINED = 0,
	BUILTIN = 1,
	MODULE = 2,
};

enum tail_func{//id for the tail callback function
    sys_enter_init = 1,
    sys_enter_submit = 2,
	sys_exit_init = 3,
	sys_exit_submit = 4,
	trace_sys_enter = 5,
	trace_sys_exit = 6,
	syscall__execve = 7,
	syscall__execveat = 8,
	sys_dup_exit_tail = 9,
	syscall__accept4 = 10,
	syscall__init_module = 11,
};

enum options{
	optDetectOrigSyscall = 1 << 0,
	optExecEnv = 1 << 1,
	optCaptureFiles = 1 << 2,
	optExtractDynCode = 1 << 3,
	optStackAddresses = 1 << 4,
	optCaptureModules = 1 << 5,
	optCgroupV1 = 1 << 6,
	optProcessInfo = 1 << 7,
	optTranslateFDFilePath = 1 << 8,
};

enum arg_types{
	/*arg_types is an enum that encodes the argument types that the BPF program may write to the shared buffer*/
	noneT = 0,
	intT,
	uintT,
	longT,
	ulongT,
	offT,
	modeT,
	devT,
	sizeT,
	pointerT,
	strT, 
	strArrT, 
	sockAddrT, 
	bytesT, 
	u16T, 
	credT, 
	intArr2T, 
	uint64ArrT, 
	u8T, 
	/*These types don't match the ones defined in the ebpf code since they are not being used by syscalls arguments.*/
	argsArrT = 0x80,
	boolT,
};

struct bpf_progs_desc{
	char name[256];
	enum bpf_prog_type type;
	int map_prog_idx;
	struct bpf_program *prog;
};

struct bpf_config_entry{
    int tracee_pid;
    int options;
    int filters;
    int cgroup_v1_hid;
    long long int uid_max;
    long long int uid_min;
    long long int pid_max;
    long long int pid_min;
    long long int mnt_ns_max;
    long long int mnt_ns_min;
    long long int pid_ns_max;
    long long int pid_ns_min;
    char events_to_submit[128]; // use 8*128 bits to describe up to 1024 events
}bpf_config_entry_t;

struct Event* Get(int eventId){// gets the Event and also returns bool to check for existance
	if(eventId <= MAX_EVENT_NUM){
		return &eventDefinitions[eventId];
	} else {
		fprintf(stderr, "the event is not exit!\n");
		return NULL;
	}
}

enum arg_types GetParamType(char *paramType){
	if(strcmp(paramType, "int") == 0 || strcmp(paramType, "pid_t") == 0 || strcmp(paramType, "uid_t") == 0 || strcmp(paramType, "gid_t") == 0 || strcmp(paramType, "mqd_t") == 0\
	|| strcmp(paramType, "clockid_t") == 0 || strcmp(paramType, "const clockid_t") == 0 || strcmp(paramType, "key_t") == 0 || strcmp(paramType, "key_serial_t") == 0 ||\
	strcmp(paramType, "timer_t") == 0){
		return intT;
	} else if(strcmp(paramType, "unsigned int") == 0 || strcmp(paramType, "u32") == 0 ){
		return uintT;
	} else if(strcmp(paramType, "long") == 0){
		return longT;
	} else if(strcmp(paramType, "unsigned long") == 0 || strcmp(paramType, "u64") == 0){
		return ulongT;
	} else if(strcmp(paramType, "bool") == 0){
		return boolT;
	} else if(strcmp(paramType, "off_t") == 0 || strcmp(paramType, "loff_t") == 0){
		return offT;
	} else if(strcmp(paramType, "mode_t") == 0){
		return modeT;
	} else if(strcmp(paramType, "dev_t") == 0){
		return devT;
	} else if(strcmp(paramType, "size_t") == 0){
		return sizeT;
	} else if(strcmp(paramType, "void*") == 0 || strcmp(paramType, "const void*") == 0){
		return pointerT;
	} else if(strcmp(paramType, "char*") == 0 || strcmp(paramType, "const char*") == 0){
		return strT;
	} else if(strcmp(paramType, "const char*const*") == 0){
		return strArrT;
	} else if(strcmp(paramType, "const char**") == 0){
		return argsArrT;
	} else if(strcmp(paramType, "const struct sockaddr*") == 0 || strcmp(paramType, "struct sockaddr*") == 0){
		return sockAddrT;
	} else if(strcmp(paramType, "bytes") == 0){
		return bytesT;
	} else if(strcmp(paramType, "int[2]") == 0){
		return intArr2T;
	} else if(strcmp(paramType, "slim_cred_t") == 0){
		return credT;
	} else if(strcmp(paramType, "umode_t") == 0){
		return u16T;
	} else if(strcmp(paramType, "u8") == 0){
		return u8T;
	} else if (strcmp(paramType, "unsigned long[]") == 0 || strcmp(paramType, "[]trace.HookedSymbolData") == 0){
		return uint64ArrT;
	} else {
		return pointerT;
	}
}

static struct bpf_progs_desc sys_enter_init_tail_progs[] = {
	{"tracepoint__raw_syscalls__sys_enter", BPF_PROG_TYPE_RAW_TRACEPOINT, -1, NULL},
	{"sys_enter_init", BPF_PROG_TYPE_RAW_TRACEPOINT, sys_enter_init, NULL},
};

static struct bpf_progs_desc sys_exit_init_tail_progs[] = {
	{"tracepoint__raw_syscalls__sys_exit", BPF_PROG_TYPE_RAW_TRACEPOINT, -1, NULL},
	{"sys_exit_init", BPF_PROG_TYPE_RAW_TRACEPOINT, sys_exit_init, NULL},
};

static struct bpf_progs_desc sys_enter_submit_tail_progs[] = {
	{"sys_enter_submit", BPF_PROG_TYPE_RAW_TRACEPOINT, sys_enter_submit, NULL},
};

static struct bpf_progs_desc sys_exit_submit_tail_progs[] = {
	{"sys_exit_submit", BPF_PROG_TYPE_RAW_TRACEPOINT, sys_exit_submit, NULL},
};

static struct bpf_progs_desc sys_enter_tails_progs[] = {
	{"trace_sys_enter", BPF_PROG_TYPE_RAW_TRACEPOINT, trace_sys_enter, NULL},
	{"syscall__execve", BPF_PROG_TYPE_RAW_TRACEPOINT, syscall__execve, NULL},
	{"syscall__execveat", BPF_PROG_TYPE_RAW_TRACEPOINT, syscall__execveat, NULL},
	{"syscall__accept4", BPF_PROG_TYPE_RAW_TRACEPOINT, syscall__accept4, NULL},
	{"syscall__init_module", BPF_PROG_TYPE_RAW_TRACEPOINT, syscall__init_module, NULL},
};

static struct bpf_progs_desc sys_exit_tails_progs[] = {
	{"trace_sys_exit", BPF_PROG_TYPE_RAW_TRACEPOINT, trace_sys_exit, NULL},
	{"sys_dup_exit_tail", BPF_PROG_TYPE_RAW_TRACEPOINT, sys_dup_exit_tail, NULL},
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

#define MAX_LINE 1024
char buf[MAX_LINE];

int main(int argc, char **argv){
	struct tracee_bpf *skel;
	int prog_count, err;
	FILE *p = NULL;
	char *split[2];
	int i = 0, flag = 0, key, value;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = tracee_bpf__open();
	if (!skel){
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = tracee_bpf__load(skel);
	if (err){
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	/* kconfig_map initial*/
	struct bpf_map *bpf_kconfig_map;
	bpf_kconfig_map = bpf_object__find_map_by_name(skel->obj, "kconfig_map");
	p = fopen("/boot/config-5.10.0-60.32.0.61.oe2203.aarch64", "r");
	if(p == NULL){
		fprintf(stderr, "failed to open the config file!\n");
		goto cleanup;
	} 
	while(fgets(buf, MAX_LINE, p) != NULL){
		i = 0;
		char *temp = strtok(buf, "=");
		while(temp){
			if(i >= 2){
				flag = 1;
				break;
			}
			split[i++] = temp;
			temp = strtok(NULL, "=");
		}

		if(flag || i < 2){
			flag = 0;
			continue;
		}
		
		if(strcmp(split[0], "CONFIG_ARCH_HAS_SYSCALL_WRAPPER") == 0){
			key = 1000U;
			if(!strcmp(split[1], "y\n")){
				value = BUILTIN;
			}else{
				value = UNDEFINED;
			}
			err = bpf_map__update_elem(bpf_kconfig_map, &key, 4, &value, 4, 0);
			if (err){
				fprintf(stderr, "Error: bpf_map_update_elem failed for kconfig map\n");
				goto cleanup;
			}
			break;
		}
	}

	/* config_map initial: close all filters*/
	int cZero = 0;
	int event_num = sizeof(eventDefinitions) / sizeof(eventDefinitions[0]);
	bpf_config_entry_t.tracee_pid = (int)getpid();
	bpf_config_entry_t.options = optDetectOrigSyscall |	optExecEnv |optCaptureFiles | optExtractDynCode |\
	optStackAddresses | optCaptureModules | optProcessInfo | optTranslateFDFilePath;
	bpf_config_entry_t.filters = 0;
	bpf_config_entry_t.cgroup_v1_hid = 0;
	bpf_config_entry_t.uid_max = 0;
	bpf_config_entry_t.uid_min = 0;
	bpf_config_entry_t.pid_max = 0;
	bpf_config_entry_t.pid_min = 0;
	bpf_config_entry_t.mnt_ns_max = 0;
	bpf_config_entry_t.mnt_ns_min = 0;
	bpf_config_entry_t.pid_ns_max = 0;
	bpf_config_entry_t.pid_ns_min = 0;
	for(int i = 0; i < event_num; ++i){
		if(eventDefinitions[i].ID32Bit >= MAX_EVENT_NUM){
			continue;
		}
		int index = eventDefinitions[i].ID32Bit / 8;
		int offset = eventDefinitions[i].ID32Bit % 8;
		bpf_config_entry_t.events_to_submit[index] = bpf_config_entry_t.events_to_submit[index] | (1 << offset);
	}
	
	struct bpf_map *bpf_config_map;
	bpf_config_map = bpf_object__find_map_by_name(skel->obj, "config_map");
	err = bpf_map__update_elem(bpf_config_map, &cZero, 4, &bpf_config_entry_t, sizeof(struct bpf_config_entry), 0);
	if (err){
		fprintf(stderr, "Error: bpf_map_update_elem failed for config map\n");
		goto cleanup;
	}

	/* sys_32_to_64_map initial */
	struct bpf_map *bpf_sys_32_to_64_map;
	bpf_sys_32_to_64_map = bpf_object__find_map_by_name(skel->obj, "sys_32_to_64_map");
	for(int i = 0; i < event_num; ++i){
		key = eventDefinitions[i].ID32Bit;
		value = eventDefinitions[i].ID64Bit;
		err = bpf_map__update_elem(bpf_sys_32_to_64_map, &key, 4, &value, 4, 0);
		if (err){
			fprintf(stderr, "Error: bpf_map_update_elem failed for sys_32_to_64 map\n");
			goto cleanup;
		}
	}

	/* params_types_map initial */
	unsigned long long int paramsTypes, temp;
	struct bpf_map *bpf_params_types_map;
	bpf_params_types_map = bpf_object__find_map_by_name(skel->obj, "params_types_map");
	for(int i = 0; i < event_num; ++i){
		paramsTypes = 0;
		for(int j = 0; j < eventDefinitions[i].Argnum; ++j){
			temp = (unsigned long long int)GetParamType(eventDefinitions[i].Params[j].Type);
			if(i == 0){
				fprintf(stderr, "temp = %lld\n", temp);
			}
			paramsTypes = paramsTypes | (temp << (8 * j));
			if(i == 0){
				fprintf(stderr, "pT = %lld\n", paramsTypes);
			}
		}
		key = eventDefinitions[i].ID64Bit;
		err = bpf_map__update_elem(bpf_params_types_map, &key, 4, &paramsTypes, 8, 0);
		if (err){
			fprintf(stderr, "Error: bpf_map_update_elem failed for params_types map\n");
			goto cleanup;
		}
	}

	key = 63;
	bpf_map__lookup_elem(bpf_params_types_map, &key, 4, &value, 8, 0);
	fprintf(stderr, "value = %d\n", value);

	/* sys_enter_init_tail_progs & sys_enter_init_tail initial*/
	struct bpf_map *map_progs;
	map_progs = bpf_object__find_map_by_name(skel->obj, "sys_enter_init_tail");
	prog_count = sizeof(sys_enter_init_tail_progs) / sizeof(sys_enter_init_tail_progs[0]);
	for (int i = 0; i < prog_count; i++){
		sys_enter_init_tail_progs[i].prog = bpf_object__find_program_by_name(skel->obj, sys_enter_init_tail_progs[i].name);
		if (!sys_enter_init_tail_progs[i].prog){
			fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
			goto cleanup;
		}
		bpf_program__set_type(sys_enter_init_tail_progs[i].prog, sys_enter_init_tail_progs[i].type);
	}

	for (int i = 0; i < prog_count; i++){
	int prog_fd = bpf_program__fd(sys_enter_init_tail_progs[i].prog);
		if (prog_fd < 0){
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", sys_enter_init_tail_progs[i].name);
			goto cleanup;
		}
 
		if (sys_enter_init_tail_progs[i].map_prog_idx != -1){
			unsigned int map_prog_idx = sys_enter_init_tail_progs[i].map_prog_idx;
			if (map_prog_idx < 0){
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", sys_enter_init_tail_progs[i].name);
				goto cleanup;
			}
			err = bpf_map__update_elem(map_progs, &map_prog_idx, 4, &prog_fd, 4, 0);
			if (err){
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				goto cleanup;
			}
		}
	}

	/* sys_exit_init_tail_progs & sys_exit_init_tail initial*/
	map_progs = bpf_object__find_map_by_name(skel->obj, "sys_exit_init_tail");
	prog_count = sizeof(sys_exit_init_tail_progs) / sizeof(sys_exit_init_tail_progs[0]);
	for (int i = 0; i < prog_count; i++){
		sys_exit_init_tail_progs[i].prog = bpf_object__find_program_by_name(skel->obj, sys_exit_init_tail_progs[i].name);
		if (!sys_exit_init_tail_progs[i].prog){
			fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
			goto cleanup;
		}
		bpf_program__set_type(sys_exit_init_tail_progs[i].prog, sys_exit_init_tail_progs[i].type);
	}

	for (int i = 0; i < prog_count; i++){
		int prog_fd = bpf_program__fd(sys_exit_init_tail_progs[i].prog);
		if (prog_fd < 0){
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", sys_exit_init_tail_progs[i].name);
			goto cleanup;
		}

		if (sys_exit_init_tail_progs[i].map_prog_idx != -1){
			unsigned int map_prog_idx = sys_exit_init_tail_progs[i].map_prog_idx;
			if (map_prog_idx < 0){
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", sys_exit_init_tail_progs[i].name);
				goto cleanup;
			}
			err = bpf_map__update_elem(map_progs, &map_prog_idx, 4, &prog_fd, 4, 0);
			if (err){
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				goto cleanup;
			}
		}
	}

	/* sys_enter_submit_tail_progs & sys_enter_submit_tail initial*/
	map_progs = bpf_object__find_map_by_name(skel->obj, "sys_enter_submit_tail");
	prog_count = sizeof(sys_enter_submit_tail_progs) / sizeof(sys_enter_submit_tail_progs[0]);
	for (int i = 0; i < prog_count; i++){
		sys_enter_submit_tail_progs[i].prog = bpf_object__find_program_by_name(skel->obj, sys_enter_submit_tail_progs[i].name);
		if (!sys_enter_submit_tail_progs[i].prog){
			fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
			goto cleanup;
		}
		bpf_program__set_type(sys_enter_submit_tail_progs[i].prog, sys_enter_submit_tail_progs[i].type);
	}

	for (int i = 0; i < prog_count; i++){
		int prog_fd = bpf_program__fd(sys_enter_submit_tail_progs[i].prog);
		if (prog_fd < 0){
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", sys_enter_submit_tail_progs[i].name);
			goto cleanup;
		}
 
		if (sys_enter_submit_tail_progs[i].map_prog_idx != -1){
			unsigned int map_prog_idx = sys_enter_submit_tail_progs[i].map_prog_idx;
			if (map_prog_idx < 0){
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", sys_enter_submit_tail_progs[i].name);
				goto cleanup;
			}
    
			err = bpf_map__update_elem(map_progs, &map_prog_idx, 4, &prog_fd, 4, 0);
			if (err){
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				goto cleanup;
			}
		}
	}

	/* sys_exit_submit_tail_progs & sys_exit_submit_tail initial*/
	map_progs = bpf_object__find_map_by_name(skel->obj, "sys_exit_submit_tail");
	prog_count = sizeof(sys_exit_submit_tail_progs) / sizeof(sys_exit_submit_tail_progs[0]);
	for (int i = 0; i < prog_count; i++){
		sys_exit_submit_tail_progs[i].prog = bpf_object__find_program_by_name(skel->obj, sys_exit_submit_tail_progs[i].name);
		if (!sys_exit_submit_tail_progs[i].prog){
			fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
			goto cleanup;
		}
		bpf_program__set_type(sys_exit_submit_tail_progs[i].prog, sys_exit_submit_tail_progs[i].type);
	}

	for (int i = 0; i < prog_count; i++){
		int prog_fd = bpf_program__fd(sys_exit_submit_tail_progs[i].prog);
		if (prog_fd < 0){
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", sys_exit_submit_tail_progs[i].name);
			goto cleanup;
		}
 
		if (sys_exit_submit_tail_progs[i].map_prog_idx != -1){
			unsigned int map_prog_idx = sys_exit_submit_tail_progs[i].map_prog_idx;
			if (map_prog_idx < 0){
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", sys_exit_submit_tail_progs[i].name);
				goto cleanup;
			}
    
			err = bpf_map__update_elem(map_progs, &map_prog_idx, 4, &prog_fd, 4, 0);
			if (err){
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				goto cleanup;
			}
		}
	}

	/* sys_enter_tails_progs & sys_enter_tails initial*/
	map_progs = bpf_object__find_map_by_name(skel->obj, "sys_enter_tails");
	prog_count = sizeof(sys_enter_tails_progs) / sizeof(sys_enter_tails_progs[0]);
	for (int i = 0; i < prog_count; i++){
		sys_enter_tails_progs[i].prog = bpf_object__find_program_by_name(skel->obj, sys_enter_tails_progs[i].name);
		if (!sys_enter_tails_progs[i].prog){
			fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
			goto cleanup;
		}
		bpf_program__set_type(sys_enter_tails_progs[i].prog, sys_enter_tails_progs[i].type);
	}

	for (int i = 0; i < prog_count; i++){
		int prog_fd = bpf_program__fd(sys_enter_tails_progs[i].prog);
		if (prog_fd < 0){
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", sys_enter_tails_progs[i].name);
			goto cleanup;
		}
 
		if (sys_enter_tails_progs[i].map_prog_idx != -1){
			unsigned int map_prog_idx = sys_enter_tails_progs[i].map_prog_idx;
			if (map_prog_idx < 0){
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", sys_enter_tails_progs[i].name);
				goto cleanup;
			}
    
			err = bpf_map__update_elem(map_progs, &map_prog_idx, 4, &prog_fd, 4, 0);
			if (err){
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				goto cleanup;
			}
		}
	}

	/* sys_exit_tails_progs & sys_exit_tails initial*/
	map_progs = bpf_object__find_map_by_name(skel->obj, "sys_exit_tails");
	prog_count = sizeof(sys_exit_tails_progs) / sizeof(sys_exit_tails_progs[0]);
	for (int i = 0; i < prog_count; i++){
		sys_exit_tails_progs[i].prog = bpf_object__find_program_by_name(skel->obj, sys_exit_tails_progs[i].name);
		if (!sys_exit_tails_progs[i].prog){
			fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
			goto cleanup;
		}
		bpf_program__set_type(sys_exit_tails_progs[i].prog, sys_exit_tails_progs[i].type);
	}

	for (int i = 0; i < prog_count; i++){
		int prog_fd = bpf_program__fd(sys_exit_tails_progs[i].prog);
		if (prog_fd < 0){
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", sys_exit_tails_progs[i].name);
			goto cleanup;
		}
 
		if (sys_exit_tails_progs[i].map_prog_idx != -1){
			unsigned int map_prog_idx = sys_exit_tails_progs[i].map_prog_idx;
			if (map_prog_idx < 0){
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", sys_exit_tails_progs[i].name);
				goto cleanup;
			}
    
			err = bpf_map__update_elem(map_progs, &map_prog_idx, 4, &prog_fd, 4, 0);
			if (err){
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				goto cleanup;
			}
		}
	}
	
	/* Attach tracepoint handler */
	struct bpf_link* link;
	link = bpf_program__attach(skel->progs.tracepoint__raw_syscalls__sys_enter);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__raw_syscalls__sys_enter attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__raw_syscalls__sys_exit);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__raw_syscalls__sys_exit attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__sched__sched_process_fork);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__sched__sched_process_fork attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__sched__sched_process_exec);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__sched__sched_process_exec attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__sched__sched_process_exit);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__sched__sched_process_exit attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__sched__sched_switch);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__sched__sched_switch attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__cgroup__cgroup_attach_task);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__cgroup__cgroup_attach_task attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__cgroup__cgroup_mkdir);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__cgroup__cgroup_mkdir attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__cgroup__cgroup_rmdir);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__cgroup__cgroup_rmdir attach failed\n");
		goto cleanup;
	}

	// link = bpf_program__attach(skel->progs.tracepoint__inet_sock_set_state);
	// if (link == NULL){
	// 	fprintf(stderr, "Error: bpf_program:tracepoint__inet_sock_set_state attach failed\n");
	// 	goto cleanup;
	// }

	link = bpf_program__attach(skel->progs.tracepoint__inet_sock_set_state);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__inet_sock_set_state attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.tracepoint__task__task_rename);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:tracepoint__task__task_rename attach failed\n");
		goto cleanup;
	}
	/* Attach kprobe handler */
	link = bpf_program__attach(skel->progs.trace_filldir64);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_filldir64 attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_call_usermodehelper);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_call_usermodehelper attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_do_exit);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_do_exit attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_bprm_check);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_bprm_check attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_file_open);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_file_open attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_sb_mount);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_sb_mount attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_inode_unlink);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_inode_unlink attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_commit_creds);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_commit_creds attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_switch_task_namespaces);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_switch_task_namespaces attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_cap_capable);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_cap_capable attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_socket_create);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_socket_create attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_inode_symlink);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_inode_symlink attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_proc_create);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_proc_create attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_debugfs_create_file);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_debugfs_create_file attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_debugfs_create_dir);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_debugfs_create_dir attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_socket_listen);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_socket_listen attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_socket_connect);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_socket_connect attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_socket_accept);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_socket_accept attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_socket_bind);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_socket_bind attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_socket_setsockopt);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_socket_setsockopt attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_udp_sendmsg);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_udp_sendmsg attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_udp_disconnect);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_udp_disconnect attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_udp_destroy_sock);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_udp_destroy_sock attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_udpv6_destroy_sock);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_udpv6_destroy_sock attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_tcp_connect);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_tcp_connect attach failed\n");
		goto cleanup;
	}

	// link = bpf_program__attach(skel->progs.trace_icmp_send);
	// if (link == NULL){
	// 	fprintf(stderr, "Error: bpf_program:trace_icmp_send attach failed\n");
	// 	goto cleanup;
	// }

	link = bpf_program__attach(skel->progs.trace_icmp6_send);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_icmp6_send attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_icmp_rcv);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_icmp_rcv attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_icmpv6_rcv);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_icmpv6_rcv attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ping_v4_sendmsg);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ping_v4_sendmsg attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ping_v6_sendmsg);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ping_v6_sendmsg attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_vfs_write);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_vfs_write attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ret_vfs_write);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ret_vfs_write attach failed\n");
		goto cleanup;
	}

	// link = bpf_program__attach(skel->progs.trace_ret_vfs_write_tail);
	// if (link == NULL){
	// 	fprintf(stderr, "Error: bpf_program:trace_ret_vfs_write_tail attach failed\n");
	// 	goto cleanup;
	// }

	link = bpf_program__attach(skel->progs.trace_vfs_writev);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_vfs_writev attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ret_vfs_writev);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ret_vfs_writev attach failed\n");
		goto cleanup;
	}

	// link = bpf_program__attach(skel->progs.trace_ret_vfs_writev_tail);
	// if (link == NULL){
	// 	fprintf(stderr, "Error: bpf_program:trace_ret_vfs_writev_tail attach failed\n");
	// 	goto cleanup;
	// }

	link = bpf_program__attach(skel->progs.trace_kernel_write);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_kernel_write attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ret_kernel_write);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ret_kernel_write attach failed\n");
		goto cleanup;
	}

	// link = bpf_program__attach(skel->progs.trace_ret_kernel_write_tail);
	// if (link == NULL){
	// 	fprintf(stderr, "Error: bpf_program:trace_ret_kernel_write_tail attach failed\n");
	// 	goto cleanup;
	// }

	link = bpf_program__attach(skel->progs.trace_mmap_alert);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_mmap_alert attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_mmap_file);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_mmap_file attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_file_mprotect);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_file_mprotect attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_bpf);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_bpf attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_register_kprobe);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_register_kprobe attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ret_register_kprobe);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ret_register_kprobe attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_bpf_map);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_bpf_map attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_kernel_read_file);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_kernel_read_file attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_kernel_post_read_file);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_kernel_post_read_file attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_inode_mknod);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_inode_mknod attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_device_add);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_device_add attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace___register_chrdev);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace__register_chrdev attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ret__register_chrdev);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ret__register_chrdev attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_do_splice);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace__register_chrdev attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ret_do_splice);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ret_do_splice attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_do_init_module);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_do_init_module attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_ret_do_init_module);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_ret_do_init_module attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_load_elf_phdrs);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_load_elf_phdrs attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_file_permission);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_file_permission attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_security_inode_rename);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_security_inode_rename attach failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(skel->progs.trace_do_sigaction);
	if (link == NULL){
		fprintf(stderr, "Error: bpf_program:trace_do_sigaction attach failed\n");
		goto cleanup;
	}
	/* Attach uprobe handler */
	// link = bpf_program__attach(skel->progs.uprobe_syscall_trigger);
	// if (link == NULL){
	// 	fprintf(stderr, "Error: bpf_program:uprobe_syscall_trigger attach failed\n");
	// 	goto cleanup;
	// }

	// link = bpf_program__attach(skel->progs.uprobe_seq_ops_trigger);
	// if (link == NULL){
	// 	fprintf(stderr, "Error: bpf_program:uprobe_seq_ops_trigger attach failed\n");
	// 	goto cleanup;
	// }
	/* Attach tracepoint handler */
	// err = tracee_bpf__attach(skel);
	// if (err){
	// 	fprintf(stderr, "Failed to attach BPF skeleton\n");
	// 	goto cleanup;
	// }

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	"to see output of the BPF programs.\n");

	for (;;){
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	tracee_bpf__destroy(skel);
	return -err;
}

