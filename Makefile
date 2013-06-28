obj-m += kmerwall.o
kmerwall-objs := merwall_module.o merwall_common.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall merwall_admin.c merwall_common.c -o ./merwall_admin

admin:
	gcc -Wall merwall_admin.c merwall_common.c -o ./merwall_admin

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f ./merwall_admin
