ifneq  ($(KERNELRELEASE),)
obj-m:=piehook.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)
all:
	echo $(KDIR)
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -f *.ko *.o *.symvers *.cmd *.cmd.o *.order *.mod.c
	rm -rf .[a-zA-Z]*
endif
