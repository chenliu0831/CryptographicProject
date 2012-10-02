#include <linux/posix_acl_xattr.h>
#include <linux/posix_acl.h>

#define ECRYPTFS_ACL_VERSION        0x0001

#define CONFIG_ECRYPTFS_POSIX_ACL

#define ECRYPTFS_POSIX_ACL_XATTR_ACCESS	"system.posix_acl_access_ecryptfs"
#define ECRYPTFS_POSIX_ACL_XATTR_DEFAULT "system.posix_acl_default_ecryptfs"

typedef struct {
	__le32	a_version;
} ecryptfs_acl_header;

typedef struct {
	__le16          e_tag;
	__le16          e_perm;
	__le32          e_id;
} ecryptfs_acl_entry;

typedef struct {
	__le16          e_tag;
	__le16          e_perm;
} ecryptfs_acl_entry_short;


static inline size_t ecryptfs_acl_size(int count)
{
	return sizeof(ecryptfs_acl_header) +
		count * sizeof(ecryptfs_acl_entry);
}

static inline int ecryptfs_acl_count(size_t size)
{
	ssize_t s;

	size -= sizeof(ecryptfs_acl_header);
	s = size;

	if (s % sizeof(ecryptfs_acl_entry))
		return -1;

	return s / sizeof(ecryptfs_acl_entry);
}


static inline
struct timespec ecryptfs_current_time(struct inode *inode)
{
	return (inode->i_sb->s_time_gran < NSEC_PER_SEC) ?
		current_fs_time(inode->i_sb) : CURRENT_TIME_SEC;
}
#ifdef CONFIG_ECRYPTFS_POSIX_ACL
#else
#include <linux/sched.h>
#define ext4_get_acl NULL

static inline int ecryptfs_acl_chmod(struct inode *inode)
{
	return 0;
}

#endif
