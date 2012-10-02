WRAPFS_VERSION="0.1"

EXTRA_CFLAGS += -DWRAPFS_VERSION=\"$(WRAPFS_VERSION)\"

obj-$(CONFIG_WRAP_FS) += wrapfs.o

OBJS  	:= manage_key.o
CC    	:= gcc
USR_CFLAGS 	:= -Wall -Werror -c
USR_LFLAGS 	:= -Wall -lssl


EXTRA_CFLAGS += -DWRAPFS_TEST
#EXTRA_CFLAGS += -DWRAPFS_CRYPTO
#EXTRA_CFLAGS += -DEXTRA_CREDIT


wrapfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o read_write.o crypto.o

manage_key: manage_key.h
	$(CC) $(USR_CFLAGS) manage_key.c	 
	$(CC) $(USR_LFLAGS) $(OBJS) -o manage_key
clean:
	rm manage_key.o manage_key
