/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _WRAPFS_H_
#define _WRAPFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/writeback.h>
#include <linux/ioctl.h>
#include <linux/linkage.h>

/* the file system name */
#define WRAPFS_NAME "wrapfs"

/* wrapfs root inode number */
#define WRAPFS_ROOT_INO     1

#define WRAPFS_MAX_KEY_LEN 32
#define WRAPFS_MAX_IV_LEN 16
#define MD5_DIGEST_SIZE   32
#define WRAPFS_DEF_CIPHER "aes"
#define WRAPFS_DEFAULT_HASH "md5"
#define WRAPFS_DEFAULT_IV_BYTES 16
/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/*Extra Credit B: Debugging Error*/
#define UDBG_EXIT(RC) printk(KERN_DEFAULT "DBGEXIT:%s:%s:%d: Return [%d]\n",\
			     __FILE__, __func__, __LINE__,RC)
 
/*for ioctl*/
#define WRAPFS_MAGIC_NUM 0x43
#define WRAPFS_SET_KEY _IOW(WRAPFS_MAGIC_NUM,1,char *)
#define WRAPFS_REVOKE_KEY _IO(WRAPFS_MAGIC_NUM,2)
#define WRAPFS_IOC_MAXNR 4

/* operations vectors defined in specific files */
extern const struct file_operations wrapfs_main_fops;
extern const struct file_operations wrapfs_dir_fops;
extern const struct inode_operations wrapfs_main_iops;
extern const struct inode_operations wrapfs_dir_iops;
extern const struct inode_operations wrapfs_symlink_iops;
extern const struct super_operations wrapfs_sops;
extern const struct dentry_operations wrapfs_dops;
extern const struct address_space_operations wrapfs_aops, wrapfs_dummy_aops;
extern const struct vm_operations_struct wrapfs_vm_ops;
struct wrapfs_crypt_stat;
extern int wrapfs_init_inode_cache(void);
extern void wrapfs_destroy_inode_cache(void);
extern int wrapfs_init_dentry_cache(void);
extern void wrapfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd);
extern struct inode *wrapfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);

extern int wrapfs_init_crypt_stat(struct wrapfs_crypt_stat *crypt_stat);
int wrapfs_compute_root_iv(struct wrapfs_crypt_stat *crypt_stat);
extern void wrapfs_destroy_crypt_stat(struct wrapfs_crypt_stat *crypt_stat);
int wrapfs_read_lower(struct file *lower_file,char *data, loff_t offset, size_t size);
int wrapfs_read_lower_page_segment(struct file* lower_file,struct page *page_upper,
				   pgoff_t page_index,
				   size_t offset_in_page,size_t size);
int wrapfs_encrypt_page(struct page *page,struct page *lower_page);

int wrapfs_decrypt_page(struct page *page, struct file *lower_file);

int wrapfs_truncate(struct dentry *dentry, loff_t new_length);
/*Mount option flag*/
extern int use_mmap;
#ifdef EXTRA_CREDIT

/*EXTRA A*/
#define WRAPFS_FILENAME_PREFIX_SIZE 24
                             
#define WRAPFS_FILENAME_PREFIX "WRAPFS_EXTRA_CREDIT_ENC."


struct wrapfs_filename{

	char *filename;
	char *encrypted_filename;
	size_t filename_size;
	size_t encrypted_filename_size;
};


struct wrapfs_getdents_callback {
	void *dirent;
	struct dentry *dentry;
	filldir_t filldir;
	int filldir_called;
	int entries_written;
};

int wrapfs_encrypt_encode_filename(char **encoded_name,
				   size_t *encoded_name_size,
				   struct wrapfs_crypt_stat *crypt_stat,
				   const char *name, size_t name_size);

int wrapfs_decode_and_decrypt_filename(char **plaintext_name,
					 size_t *plaintext_name_size,
					 struct dentry *wrapfs_dir_dentry,
				       const char *name, size_t name_size);
/*EXTRA B*/
extern int dbg_bitmap;
#define DBG_SB_OP        0x00000001
#define DBG_INODE_OP     0x00000002
#define DBG_DENTRY_OP    0x00000004
#define DBG_FILE_OP      0x00000010
#define DBG_ADDR_OP      0x00000020
#define DBG_OTHER_OP     0x00000040




#endif

#define WRAPFS_ZERO      0x00000000


#define WRAPFS_KEY_SET   0x00000001
#define WRAPFS_KEY_NULL  0x00000002
struct wrapfs_crypt_stat{
        
	u32 flags;
        size_t iv_bytes;
	size_t key_size;

	struct crypto_blkcipher *tfm;
	struct crypto_hash *hash_tfm;
	unsigned char key[WRAPFS_MAX_KEY_LEN];
	unsigned char root_iv[WRAPFS_MAX_IV_LEN];
	
	
	struct mutex cs_tfm_mutex;
	struct mutex cs_hash_tfm_mutex;
	

};


/* file private data */
struct wrapfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* wrapfs inode data in memory */
struct wrapfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
	/*
	struct mutex lower_file_mutex;
	struct file *lower_file;
	*/
};

/* wrapfs dentry data in memory */
struct wrapfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

/* wrapfs super-block data in memory */
struct wrapfs_sb_info {
	struct super_block *lower_sb;
	struct wrapfs_crypt_stat crypt_stat;
	
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * wrapfs_inode_info structure, WRAPFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct wrapfs_inode_info *WRAPFS_I(const struct inode *inode)
{
	return container_of(inode, struct wrapfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define WRAPFS_D(dent) ((struct wrapfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define WRAPFS_SB(super) ((struct wrapfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define WRAPFS_F(file) ((struct wrapfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *wrapfs_lower_file(const struct file *f)
{
	return WRAPFS_F(f)->lower_file;
}

static inline void wrapfs_set_lower_file(struct file *f, struct file *val)
{
	WRAPFS_F(f)->lower_file = val;
}


/* inode to lower inode. */
static inline struct inode *wrapfs_lower_inode(const struct inode *i)
{
	return WRAPFS_I(i)->lower_inode;
}

static inline void wrapfs_set_lower_inode(struct inode *i, struct inode *val)
{
	WRAPFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *wrapfs_lower_super(
	const struct super_block *sb)
{
	return WRAPFS_SB(sb)->lower_sb;
}

static inline void wrapfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	WRAPFS_SB(sb)->lower_sb = val;
}
/*dentry to lower dentry*/

static inline struct dentry* wrapfs_dentry_to_lower(struct dentry *dentry)
{
	return (WRAPFS_D(dentry)->lower_path.dentry);
}
/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void wrapfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(lower_path, &WRAPFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void wrapfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&WRAPFS_D(dent)->lower_path, lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	WRAPFS_D(dent)->lower_path.dentry = NULL;
	WRAPFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&lower_path, &WRAPFS_D(dent)->lower_path);
	WRAPFS_D(dent)->lower_path.dentry = NULL;
	WRAPFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

/* for locking a super_block.*/
enum wrapfs_superb_lock_class{
	WRAPFS_SMUTEX_NORMAL,
	WRAPFS_SMUTEX_PARENT, /*file*/
	WRAPFS_SMUTEX_CHILD  /*dentry*/
};


int wrapfs_get_iv(char *iv,struct wrapfs_crypt_stat *crypt_stat,
		  loff_t offset);

static inline void wrapfs_read_lock(struct super_block *sb, int subclass)
{
	

}
#endif	/* not _WRAPFS_H_ */
