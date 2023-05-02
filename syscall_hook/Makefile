ARCH = arm64
CROSS_COMPILE = aarch64-linux-gnueabi-

BASEINCLUDE ?= /lib/modules/`uname -r`/build

testsyscall-objs := syscall_hook.o 

obj-m	:=   syscall_hook.o
all : 
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) clean;


