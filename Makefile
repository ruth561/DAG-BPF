PWD	:= $(shell pwd)
obj-m	+= dag_bpf.o


all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

install:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

insmod:
	sudo dmesg -C
	sudo insmod dag_bpf.ko
	sudo dmesg

rmmod:
	sudo dmesg -C
	sudo rmmod dag_bpf
	sudo dmesg
