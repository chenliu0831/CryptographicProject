#ifndef _MAN_KEY
#define _MAN_KEY

#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define WRAPFS_MAGIC_NUM 0x43
#define WRAPFS_SET_KEY _IOW(WRAPFS_MAGIC_NUM,1,char *)
#define WRAPFS_REVOKE_KEY _IO(WRAPFS_MAGIC_NUM,2)

#define WRAPFS_IOC_MAXNR 4

#endif
