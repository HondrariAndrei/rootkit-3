EXTRA_CFLAGS	:= -g -O2


ifneq ($(KERNELRELEASE),)

obj-m			= root.o

root-objs 	        := hide_file.o hook.o k_file.o 
else
KDIR := /home/sina/work/rootkit/linux-3.0.1

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.order *~  *.symvers

endif






