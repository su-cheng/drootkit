ARCH = arm64
CROSS_COMPILE = aarch64-linux-gnueabi-

BASEINCLUDE ?= /lib/modules/`uname -r`/build

testsyscall-objs := re_syscall.o 

obj-m	:=   re_syscall.o
all : 
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) clean;


