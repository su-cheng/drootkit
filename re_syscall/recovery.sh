#!/bin/bash

:<<EOF
	This script is used for recovery operations, including
	uninstalling the malicious kernel module and loading 
	the module used to recover the system call address.
	
	This script should not be called manually, it should be
	triggered by the drootkit tool.

	The script has two main options:
	"-i" : followed by the name of the kernel module to be loaded
	"-r" : followed by the name of the kernel module to be unloaded

	so you need to enter one parameter:
	The name of the kernel module to be unloaded or loaded
EOF

INSMOD=0
RMMOD=0
HELP=0
VERSION=0
OPARG=0
MODOBJ=unset

function usage(){
cat <<'EOF'
Usage: recovery.sh [ -i module_name ]
				[ -r module_name ]
				[ -h | --help ]
				[ -V | --version ] 
Options:
	-i     	               followed by the name of the kernel module to be loaded
	-r      	   	       followed by the name of the kernel module to be unloaded
	-h | --help  	       for more help information
	-V | --version 	       version information

These options are mutually exclusive and can only be set one at a time, 
and must be set one at a time.
EOF
}

function oparg_check(){
	local OP;
	if [ $INSMOD -eq 1 ]; then
		OP="-i";
	else
		OP="-r";
	fi
	if [[ $MODOBJ == "-"* ]] || [[ $MODOBJ = "--"* ]]; then
		echo "Invalid argument $MODOBJ for option $OP";
		echo "Please try ./recovery.sh --help for more information.";
		exit 1;
	fi
}

function noparg_check(){
	if [ $OPARG -eq 1 ]; then
		echo "No parameters are required for this option.";
                echo "Please try ./recovery.sh --help for more information.";
		exit 1;
	fi
}

function func(){
	if [ $INSMOD -eq 1 ]; then
			sudo insmod $MODOBJ
	elif [ $RMMOD -eq 1 ]; then
			sudo rmmod $MODOBJ
	fi
}

parameters=`getopt -o i:r:hV --long help,version -- "$@"`
if [ $? -ne 0 ]; then							#Invalid options or options that must take parameters are not
	echo "Please try '$0 --help' for more information."; 
	exit 1;
fi	

eval set -- "$parameters"
while true;do
	case "$1" in
		-i) INSMOD=1; MODOBJ=$2; shift 2;;
		-r) RMMOD=1; MODOBJ=$2; shift 2;;
		-V | --version) VERSION=1; shift;;
		-h | --help) HELP=1; shift;;
		--) shift ; break;;
	esac
done

REST="$@"
if [ -n "$REST" ]; then
	OPARG=1;
fi

JUGEMENT=$(( $INSMOD + $RMMOD + $HELP + $VERSION ))
if [ $JUGEMENT -eq 0 ]; then
	echo "Error: you must set one option.";
	echo "Please try '$0 --help' for more information.";
	exit 1;
elif [ $JUGEMENT -gt 1 ]; then
	echo "Error: you can only set one option"
	echo "Please try '$0 --help' for more information.";
	exit 1;
else
	if [ $INSMOD -eq 1 ]; then
		oparg_check;		
		func;
		exit 0;
	elif [ $RMMOD -eq 1 ]; then
		oparg_check;
		func;
		exit 0;
	elif [ $HELP -eq 1 ]; then
		noparg_check;
		usage;
		exit 0;
	else
		noparg_check;
		echo "$0 version 0.1";
		exit 0;	
	fi
fi


