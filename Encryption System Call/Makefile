obj-m	:= sys_xcrypt.o 
obj-y 	:= wrapper_syscall.o
OBJS  	:= xcipher.o  

CC    	:= gcc
USR_CFLAGS 	:= -Wall -Werror -c
USR_LFLAGS 	:= -Wall -lssl


override ccflags-y += -Werror -Wall
KVER := $(shell uname -r)
all: 	xcipher
	make -C /lib/modules/$(KVER)/build M=$(PWD) modules  

clean : 
	make -C /lib/modules/$(KVER)/build M=$(PWD) clean	
	\rm *.o *~ xcipher

xcipher: $(OBJS) 
	$(CC) $(USR_LFLAGS) $(OBJS) -o xcipher
xcipher.o: xcrypt_common.h
	$(CC) $(USR_CFLAGS) xcipher.c	
