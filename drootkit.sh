#!/bin/bash

:<<EOF
	This script is used to call the drootkit detection tool, 
	which monitors the system calls in the system for hijacking.
	You need to enter a parameter: 
	the path where the drootkit tool is located
	
	If you execute this script only in the current directory, 
	the command form is:
	./drootkit.sh "drootkit_path"

	If you want to encapsulate this script into a command that 
	we can run anywhere, Firstly, please copy this script into
	the /usr/bin directory, and remember to change the name of
	the copy to the name of the command you want, such as drootkit.
	then you can run this script by typing the drootkit command
	anywhere.
EOF

if [ -z $1 ];then
	echo "Please enter the path where the drootkit executable is located!"
else
	cd $1
	sudo ./drootkit
fi
