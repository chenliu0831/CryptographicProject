#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ioctl */
#define ECRYPTFS_SETACL	_IOW('g', 1, struct posix_acl *)
#define ECRYPTFS_GETACL _IOR('g', 2, struct acl_list *)

/* e_tag entry in struct posix_acl_entry */
#define ACL_USER_OBJ            (0x01)
#define ACL_USER                (0x02)
#define ACL_GROUP_OBJ           (0x04)
#define ACL_GROUP               (0x08)
#define ACL_MASK                (0x10)
#define ACL_OTHER               (0x20)
#define ACL_PROCESS		(0x03)
#define ACL_SESSION		(0x05)
#define ACL_TIME		(0x06)


/* permissions in the e_perm field */
#define ACL_READ                (0x04)
#define ACL_WRITE               (0x02)
#define ACL_EXECUTE             (0x01)

#define ACL_UNDEFINED_ID	(-1)

struct posix_acl_entry {
	short                   e_tag;
	unsigned short          e_perm;
	unsigned int            e_id;
};

struct posix_acl {
	unsigned int            a_count;
	struct posix_acl_entry  a_entries[10];
};



