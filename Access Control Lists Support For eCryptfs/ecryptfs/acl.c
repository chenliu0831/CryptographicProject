#include <linux/slab.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/jbd2.h>
#include <linux/time.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/gfp.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include "acl.h"
#include "ecryptfs_kernel.h"

static void *
ecryptfs_acl_to_disk(const struct posix_acl *acl, size_t *size)
{
	ecryptfs_acl_header *ecr_acl;
	char *e;
	size_t n;

	*size = ecryptfs_acl_size(acl->a_count);
	ecr_acl = kmalloc(sizeof(ecryptfs_acl_header) + acl->a_count *
			sizeof(ecryptfs_acl_entry), GFP_KERNEL);
	if (!ecr_acl)
		return ERR_PTR(-ENOMEM);
	ecr_acl->a_version = cpu_to_le32(ECRYPTFS_ACL_VERSION);
	e = (char *)ecr_acl + sizeof(ecryptfs_acl_header);

	for (n = 0; n < acl->a_count; n++) {
		ecryptfs_acl_entry *entry = (ecryptfs_acl_entry *)e;
		entry->e_tag = cpu_to_le16(acl->a_entries[n].e_tag);

			ecryptfs_printk(, "entry tag is %d\n",
					entry->e_tag);
		entry->e_perm = cpu_to_le16(acl->a_entries[n].e_perm);
		switch (acl->a_entries[n].e_tag) {
		case ACL_USER:
		case ACL_GROUP:
		case ACL_PROCESS:
		case ACL_SESSION:
		case ACL_TIME:
			entry->e_id = cpu_to_le32(acl->a_entries[n].e_id);
			e += sizeof(ecryptfs_acl_entry);
			ecryptfs_printk(, "Entry eid is %d\n", entry->e_id);
			break;
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			e += sizeof(ecryptfs_acl_entry_short);
			break;

		default:
			goto fail;
		}
	}
	return (char *)ecr_acl;
fail:
	kfree(ecr_acl);
	return ERR_PTR(-EINVAL);
}

static struct posix_acl *
ecryptfs_acl_from_disk(const void *value, size_t size)
{
	const char *end = (char *)value + size;
	int n, count;
	struct posix_acl *acl;

	if (!value)
		return NULL;
	if (size < sizeof(ecryptfs_acl_header))
		return ERR_PTR(-EINVAL);
	value = (char *)value + sizeof(ecryptfs_acl_header);
	count = ecryptfs_acl_count(size);
	if (count < 0)
		return ERR_PTR(-EINVAL);

	if (count == 0)
		return NULL;
	acl = posix_acl_alloc(count, GFP_NOFS);

	if (!acl)
		return ERR_PTR(-ENOMEM);
	for (n = 0; n < count; n++) {
		ecryptfs_acl_entry *entry = (ecryptfs_acl_entry *)value;
		if ((char *)value + sizeof(ecryptfs_acl_entry_short) > end)
			goto fail;
		acl->a_entries[n].e_tag = le16_to_cpu(entry->e_tag);
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm);

		switch (acl->a_entries[n].e_tag) {
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			value = (char *)value +
				sizeof(ecryptfs_acl_entry_short);
			acl->a_entries[n].e_id = ACL_UNDEFINED_ID;
			break;
		case ACL_USER:
		case ACL_GROUP:
		case ACL_PROCESS:
		case ACL_SESSION:
		case ACL_TIME:
			value = (char *)value + sizeof(ecryptfs_acl_entry);
			if ((char *)value > end)
				goto fail;
			acl->a_entries[n].e_id =
				le32_to_cpu(entry->e_id);
			break;
		default:
			goto fail;
		}
	}
	if (value != end)
		goto fail;
	return acl;
fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}


int parse_list_to_acl(char *xattr_list, char **acl_list,
			     size_t size)
{
	size_t acl_cnt = 0;
	/* parse xattr_list and copy name to acl_list */
	char *p = xattr_list;
	char *q = NULL;

	*acl_list = (char *)kmalloc(size, GFP_KERNEL);
	q = *acl_list;
	while ((p-xattr_list) <= size) {
		/* if len != 21, it's impossible to be a ACL_ name */
		if (strlen(p) != ECRYPTFS_ACL_NAME_LEN-1) {
			p = p + strlen(p) + 1;
			continue;
		}
		if (p == strstr(p, "user.ACL")) {
			memcpy(q, p, strlen(p)+1);
			/* printk("Parse: %s\n",*acl_list); */
			q += strlen(p) + 1;
			acl_cnt++;
		}
		p = p + strlen(p) + 1;
	}
	return acl_cnt;
}


int ecryptfs_list_acl(struct dentry *upper_dentry, char **list)
{
	int rc = 0;
	ssize_t size = 0;

	ecryptfs_printk(, "Entering list_acl\n");
	if (!upper_dentry->d_inode->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	size = upper_dentry->d_inode->i_op->listxattr(upper_dentry, NULL, 0);

	if (size <= 0) {
		rc = size;
		goto out;
	}

	/* allocate space for names */
	*list = (char *)kmalloc(size, GFP_KERNEL);
	if (*list == NULL) {
		ecryptfs_printk(, "Allocating [%d] bytes fail\n",
				size);
		rc = -ENOMEM;
		goto out;
	}
	/* copy xattr to list */
	rc = upper_dentry->d_inode->i_op->listxattr(upper_dentry, *list, size);
	if (rc < 0) {
		kfree(*list);
		list = NULL;
		goto out;
	}
out:

	return rc;
}

int ecryptfs_get_acl(struct dentry *dentry, int type, struct posix_acl **acl,
		 char *name)
{
	char *value = NULL;
	int retval;

	if (!dentry->d_inode->i_op->getxattr) {
		retval = -EOPNOTSUPP;
		goto out;
	}

	retval = dentry->d_inode->i_op->getxattr(dentry, name, NULL, 0);

	if (retval > 0) {
		value = kmalloc(retval, GFP_KERNEL);
		if (!value)
			return -ENOMEM;

		retval = dentry->d_inode->i_op->getxattr(dentry, name,
						       value, retval);
	}
	if (retval > 0)
		*acl = ecryptfs_acl_from_disk(value, retval);
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		*acl = ERR_PTR(retval);
	kfree(value);

out:
	return retval;
}


static int set_xattrname(char *name, int size)
{
	long time;
	struct timeval val;
	char *tempname;

	tempname = kmalloc(size, GFP_KERNEL);
	if (!tempname)
		return -ENOMEM;
	do_gettimeofday(&val);
	time = val.tv_sec;

	sprintf(tempname, "user.ACL_%011ld", time);
	memcpy(name, tempname, size);
	kfree(tempname);
	return 0;
}

int
ecryptfs_set_acl(struct dentry *dentry, int type,
		struct posix_acl *acl)
{
	void *value = NULL;
	char *name;
	size_t size = 0;
	int error;

	if (S_ISLNK(dentry->d_inode->i_mode))
		return -EOPNOTSUPP;

	if (dentry->d_inode->i_mode) {
		dentry->d_inode->i_mode &= ~S_IRWXUGO;
		dentry->d_inode->i_ctime =
			ecryptfs_current_time(dentry->d_inode);
	}

	if (acl) {
		value = ecryptfs_acl_to_disk(acl, &size);
		if (IS_ERR(value)) {
			ecryptfs_printk(, "acl_to_disk return %d\n",
					(int)PTR_ERR(value));
			return (int)PTR_ERR(value);
		}
	}
	if (value == NULL)
		return -EINVAL;

	name = kmalloc(ECRYPTFS_ACL_NAME_LEN, GFP_KERNEL);
	set_xattrname(name, ECRYPTFS_ACL_NAME_LEN);
	error = dentry->d_inode->i_op->setxattr(dentry, name, value, size, 0);

	kfree(name);
	kfree(value);

	return error;
}

static bool in_time(int time_interval)
{
	int start_time;
	int end_time;
	struct tm cal_time;
	struct timeval tv;

	printk(KERN_WARNING "in_time: timeinterval = %d\n", time_interval);
	start_time = (time_interval >> 16) & 0x0000ffff;
	end_time   = (time_interval & 0x0000ffff);

	ecryptfs_printk(, "startime:[%d], endtime[%d]\n",
			start_time, end_time);

	do_gettimeofday(&tv);
	time_to_tm(tv.tv_sec, 0, &cal_time);

	ecryptfs_printk(, "curr_time: %d\n",
			cal_time.tm_hour);

	cal_time.tm_hour = (cal_time.tm_hour + 20) % 24;
	if ((start_time <= cal_time.tm_hour) &&
	   (end_time >= cal_time.tm_hour)) {
		printk(KERN_WARNING "true\n");
		return true;
	}
	printk(KERN_WARNING "false\n");
	return false;
}


static int do_check_acl(struct inode *inode, const struct posix_acl *acl,
			int want)
{
	const struct posix_acl_entry *pa, *pe;
	struct pid *sid;
	pid_t pid;
	want &= MAY_READ | MAY_WRITE | MAY_EXEC | MAY_NOT_BLOCK;
	FOREACH_ACL_ENTRY(pa, acl, pe) {
		ecryptfs_printk(, "tag checking now is : %d\n",
				pa->e_tag);
		switch (pa->e_tag) {
		case ACL_USER:
			if (pa->e_id != current_fsuid())
				goto ACCESS_DENIED;
			break;
		case ACL_GROUP:
			if (!in_group_p(pa->e_id))
				goto ACCESS_DENIED;
			break;
		case ACL_PROCESS:
			ecryptfs_printk(, "current pid is %d\n",
					current->pid);
			if (pa->e_id != current->pid)
				goto ACCESS_DENIED;
			break;
		case ACL_SESSION:
			sid = task_session(current);
			pid = pid_vnr(sid);
			if (pa->e_id != pid)
				goto ACCESS_DENIED;
			break;
		case ACL_TIME:
			printk(KERN_WARNING "check time: %d\n", pa->e_id);
			if (!in_time(pa->e_id))
				goto ACCESS_DENIED;
			break;
		default:
			return -EIO;
		}

		if ((pa->e_perm & want) == want)
			continue;
		else
			goto ACCESS_DENIED;
	}
	return 0;

ACCESS_DENIED:
	return -EACCES;
}

int ecryptfs_acl_name_hiding(struct dentry *dentry, int want)
{
	int rc = 0;
	char *xattr_name_list = NULL;
	struct posix_acl *acl;
	char *acl_name_list = NULL;
	char *current_name;
	size_t size = 0;
	int x;
	int permission = 0;

	if ((dentry->d_name.len == 1 &&
		!strcmp(dentry->d_name.name, "."))
		|| (dentry->d_name.len == 2 &&
		!strcmp(dentry->d_name.name, ".."))) {

		return 0;
	}
	rc = ecryptfs_list_acl(dentry, &xattr_name_list);
	if (rc < 0)
		goto out;
	if (rc == 0)
		goto out;

	size = rc;
	rc = parse_list_to_acl(xattr_name_list, &acl_name_list, size);

	if (rc < 0)
		goto out;
	if (rc == 0)
		goto out;

	current_name = acl_name_list;
	/* Loop to check permission */
	x = 0;
	while (x < rc) {
		ecryptfs_get_acl(dentry, ACL_TYPE_ACCESS,
					&acl, current_name);
		permission = do_check_acl(dentry->d_inode, acl, want);
		/* if passed acl check, then grant permissoin */
		if (permission == 0) {
			rc =  permission;
			goto out;
		}
		/* else, continue to check next acl */
		x++;
		current_name += ECRYPTFS_ACL_NAME_LEN;
	}
	rc = -EACCES;
out:
	kfree(acl_name_list);
	kfree(xattr_name_list);
	ecryptfs_printk(, "dentry %p{name = %s}, refcount = %d\n",
			dentry, dentry->d_name.name,
			dentry->d_count);
	dput(dentry);

	return rc;
}

int ecryptfs_check_acl(struct inode *inode, int type, int want)
{
	int rc = 0;
	struct dentry *lower_dentry = NULL;
	char *xattr_name_list = NULL;
	struct posix_acl *acl;
	char *acl_name_list = NULL;
	char *current_name;
	size_t size = 0;
	int x;
	int permission = 0;

	lower_dentry = d_obtain_alias(inode);

	if (IS_ERR(lower_dentry)) {
		printk(KERN_WARNING "lower_dentry from inode fail!\n");
		rc = -EINVAL;
		goto out_early;
	}

	ecryptfs_printk(, "lower_dentry name %s\n",
		lower_dentry->d_name.name);
	if ((lower_dentry->d_name.len == 1 &&
		!strcmp(lower_dentry->d_name.name, "."))
		|| (lower_dentry->d_name.len == 2 &&
		!strcmp(lower_dentry->d_name.name, ".."))) {
		return 0;
	}

	/* copy all xattr name to xattr_name_list for processin */
	rc = ecryptfs_list_acl(lower_dentry, &xattr_name_list);

	if (rc < 0)
		goto out;
	if (rc == 0)
		goto out;

	/* Parse the list and get all acl name */
	size = rc;
	rc = parse_list_to_acl(xattr_name_list, &acl_name_list, size);

	if (rc < 0)
		goto out;
	if (rc == 0)
		goto out;

	current_name = acl_name_list;
	/* Loop to check permission */
	x = 0;
	while (x < rc) {
		ecryptfs_get_acl(lower_dentry, ACL_TYPE_ACCESS,
					&acl, current_name);
		permission = do_check_acl(lower_dentry->d_inode,
					  acl, want);
		/* if passed acl check, then grant permissoin */
		if (permission == 0) {
			rc = permission;
		       goto out;
		}
		/* else, continue to check next acl */
		x++;
		current_name += ECRYPTFS_ACL_NAME_LEN;
	}

	rc = -EACCES;
out:
	kfree(acl_name_list);
	kfree(xattr_name_list);
	dput(lower_dentry);

out_early:
	return rc;
}
