#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/compiler.h>
#include <linux/key.h>
#include <linux/namei.h>
#include <linux/crypto.h>
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include "wrapfs.h"
static char *aes_iv = "lcylcylcylcylccy";
static int wrapfs_decrypt_page_offset(struct wrapfs_crypt_stat *crypt_stat,
				      struct page *dst_page, int dst_offset,
				      struct page *src_page, int src_offset,
				      int size, unsigned char *iv);
static int wrapfs_encrypt_page_offset(struct wrapfs_crypt_stat *crypt_stat,
				      struct page *dst_page, int dst_offset,
				      struct page *src_page, int src_offset,
				      int size, unsigned char *iv);

int wrapfs_get_iv(char *iv,struct wrapfs_crypt_stat *crypt_stat,
		  loff_t offset)
{
	int err =0;
	char src[WRAPFS_MAX_IV_LEN];
	
	memcpy(src,crypt_stat->root_iv,crypt_stat->iv_bytes);
	
	memcpy(iv,src,crypt_stat->iv_bytes);

	return err;
}
static int wrapfs_calculate_md5(char *dst,
				struct wrapfs_crypt_stat *crypt_stat,
				char *src,int len)
{
	struct scatterlist sg;
	struct hash_desc desc = {
		.tfm = crypt_stat->hash_tfm,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	int rc =0;
	mutex_lock(&crypt_stat->cs_hash_tfm_mutex);
	sg_init_one(&sg, (u8 *)src, len);
	if (!desc.tfm) {
		desc.tfm = crypto_alloc_hash(WRAPFS_DEFAULT_HASH, 0,
					     CRYPTO_ALG_ASYNC);
		if (IS_ERR(desc.tfm)) {
			rc = PTR_ERR(desc.tfm);
			printk(KERN_ERR "Error attempting to "
					"allocate crypto context; rc = [%d]\n",
					rc);
			goto out;
		}
		crypt_stat->hash_tfm = desc.tfm;
	}
	rc = crypto_hash_init(&desc);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error initializing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
	rc = crypto_hash_update(&desc, &sg, len);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error updating crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
	rc = crypto_hash_final(&desc, dst);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error finalizing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
 out:
	mutex_unlock(&crypt_stat->cs_hash_tfm_mutex);
	return rc;
}
/*
 * @dec_extent_page: ciphertext read from lower file
   @page: decrypt to this
*/
static int wrapfs_decrypt_extent(struct page *page,
				 struct wrapfs_crypt_stat *crypt_stat,
				 struct page *dec_extent_page)
{
	loff_t extent_base;
	char extent_iv[WRAPFS_MAX_IV_LEN];
	int err =0;

	extent_base = (loff_t)(page->index);
	err = wrapfs_get_iv(extent_iv,crypt_stat,extent_base);
	if(err){
		printk(KERN_ERR "%s: Derive IV err!\n",__func__);
		goto out;
	}
	err = wrapfs_decrypt_page_offset(crypt_stat,page,0,
					 dec_extent_page,0,
					 PAGE_CACHE_SIZE,extent_iv);
	if(err <0){
		printk(KERN_ERR "%s Error decrypting page with "
		       "page->index = [%ld], rc = [%d]\n",__func__,
		       page->index,err);
		goto out;
	}
	err =0;

 out: 
	return err;
}
				 
static int wrapfs_encrypt_extent(struct page *enc_extent_page,
				 struct wrapfs_crypt_stat *crypt_stat,
				 struct page *page)
{
	loff_t extent_base;
	char extent_iv[WRAPFS_MAX_IV_LEN];
	int err;

	extent_base = (loff_t)(page->index);
	err = wrapfs_get_iv(extent_iv,crypt_stat,extent_base);
	if(err){
		printk(KERN_ERR "%s: Derive IV err!\n",__func__);
		goto out;
	}
	err = wrapfs_encrypt_page_offset(crypt_stat,enc_extent_page,0,
					 page,0,
					 PAGE_CACHE_SIZE,extent_iv);
	if(err <0){
		printk(KERN_ERR "%s Error encrypting page with "
		       "page->index = [%ld], rc = [%d]\n",__func__,
		       page->index,err);
		goto out;
	}
	err =0;
 out:
	return err;
	
}

static int decrypt_scatterlist(struct wrapfs_crypt_stat *crypt_stat,
			      struct scatterlist *dest_sg,
			      struct scatterlist *src_sg, int size,
			      unsigned char *iv)
{

	int err =0;
	struct blkcipher_desc desc = {
		.tfm = crypt_stat->tfm,
		.info = iv,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
       
	BUG_ON(!crypt_stat || !crypt_stat->tfm);

	mutex_lock(&crypt_stat->cs_tfm_mutex);

	err = crypto_blkcipher_setkey(crypt_stat->tfm,crypt_stat->key,
				      crypt_stat->key_size);
	if(err){
		printk(KERN_ERR "Error setting key, err = %d\n",err);
		mutex_unlock(&crypt_stat->cs_tfm_mutex);
		err = -EINVAL;
		goto out;
	}
	/*
	printk(KERN_DEBUG "Decrypting [%d] bytes.\n",size);
	*/
	err = crypto_blkcipher_decrypt_iv(&desc,dest_sg,src_sg,size);
	mutex_unlock(&crypt_stat->cs_tfm_mutex);

	if(err){
		printk(KERN_ERR "Error Decrypting; rc = [%d]\n",err);
		goto out;
	}
	err = size;
 out: 
	return err;
}

static int encrypt_scatterlist(struct wrapfs_crypt_stat *crypt_stat,
			      struct scatterlist *dest_sg,
			      struct scatterlist *src_sg, int size,
			      unsigned char *iv)
{
	int err =0;
	struct blkcipher_desc desc = {
		.tfm = crypt_stat->tfm,
		.info = iv,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
       
	BUG_ON(!crypt_stat || !crypt_stat->tfm);

	mutex_lock(&crypt_stat->cs_tfm_mutex);
	err = crypto_blkcipher_setkey(crypt_stat->tfm,crypt_stat->key,
				      crypt_stat->key_size);
	if(err){
		printk(KERN_ERR "Error setting key, err = %d\n",err);
		mutex_unlock(&crypt_stat->cs_tfm_mutex);
		err = -EINVAL;
		goto out;
	}
	/*
	printk(KERN_DEBUG "Encrypting [%d] bytes.\n",size);
	*/
	crypto_blkcipher_encrypt_iv(&desc,dest_sg,src_sg,size);
	mutex_unlock(&crypt_stat->cs_tfm_mutex);

 out:
	return err;
}
static int wrapfs_decrypt_page_offset(struct wrapfs_crypt_stat *crypt_stat,
				      struct page *dst_page, int dst_offset,
				      struct page *src_page, int src_offset,
				      int size, unsigned char *iv)
{
	struct scatterlist src_sg, dst_sg;
	
	sg_init_table(&src_sg,1);
	sg_set_page(&src_sg,src_page,size,src_offset);

	sg_init_table(&dst_sg,1);	
	sg_set_page(&dst_sg,dst_page,size,dst_offset);

	return decrypt_scatterlist(crypt_stat,&dst_sg,&src_sg,size,iv);
}


static int wrapfs_encrypt_page_offset(struct wrapfs_crypt_stat *crypt_stat,
				      struct page *dst_page, int dst_offset,
				      struct page *src_page, int src_offset,
				      int size, unsigned char *iv)
{
	struct scatterlist src_sg, dst_sg;
	
	sg_init_table(&src_sg,1);
	sg_init_table(&dst_sg,1);
	
	sg_set_page(&src_sg,src_page,size,src_offset);
	sg_set_page(&dst_sg,dst_page,size,dst_offset);

	return encrypt_scatterlist(crypt_stat,&dst_sg,&src_sg,size,iv);
}
int wrapfs_compute_root_iv(struct wrapfs_crypt_stat *crypt_stat)
{
	int err =0;
	char dst[MD5_DIGEST_SIZE];

	BUG_ON(crypt_stat->iv_bytes > MD5_DIGEST_SIZE);
	BUG_ON(crypt_stat->iv_bytes <=0);

	/*
	if(!(crypt_stat->flags & WRAPFS_KEY_VALID)){
		err = -EINVAL;
		printk(KERN_WARNING "Session key not valid;"
		       "cannot gen root iv\n");
		goto out;
	}
	*/
	err = wrapfs_calculate_md5(dst,crypt_stat,crypt_stat->key,
				   crypt_stat->key_size);
	if(err){
		printk(KERN_WARNING "Error computing MD5 while"
		       "generating root IV\n");
		goto out;
	}
	memcpy(crypt_stat->root_iv,dst,crypt_stat->iv_bytes);
out: 
	if(err){
		memset(crypt_stat->root_iv,0,crypt_stat->iv_bytes);
	}
	return err;
}
/*
static int wrapfs_assemble_cipher_name(char **alg_name,
				       char *modifier)
{
	char *cipher_name = "aes";
	int cipher_name_len = strlen(cipher_name);
	int modifier_len = strlen(modifier);
	int rc=0;
	int alg_name_len;
	
	alg_name_len = (modifier_len+cipher_name_len+3);
	(*alg_name) = kmalloc(alg_name_len,GFP_KERNEL);
	if(!(*alg_name)){
		rc = -ENOMEM;
		goto out;
	}

	snprintf((*alg_name),alg_name_len,"%s(%s)",
		  modifier,cipher_name);
	rc= 0;
 out:
	return rc;
	
	}*/

int wrapfs_init_crypt_stat(struct wrapfs_crypt_stat *crypt_stat)
{
	
	
	int rc = -EINVAL;
	/*For test only*/
	#ifdef WRAPFS_TEST
	char tmpkey[] = "CSE506CSE506CSE506CSE506VSSEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
	
	#endif
	
	memset((void*)crypt_stat,0,sizeof(struct wrapfs_crypt_stat));
	
	mutex_init(&crypt_stat->cs_tfm_mutex);
	mutex_init(&crypt_stat->cs_hash_tfm_mutex);
	
	crypt_stat->key_size = WRAPFS_MAX_KEY_LEN;
	crypt_stat->iv_bytes = WRAPFS_DEFAULT_IV_BYTES;
	#ifdef WRAPFS_TEST
	printk(KERN_DEBUG "It's TESTING MODE!!!!\n");
	crypt_stat->flags |= WRAPFS_KEY_SET;
	#else
	crypt_stat->flags |= WRAPFS_KEY_NULL;
	#endif

	#ifdef WRAPFS_TEST
	memcpy(crypt_stat->key,tmpkey,WRAPFS_MAX_KEY_LEN);
	rc = wrapfs_compute_root_iv(crypt_stat);
	if(rc){
		printk(KERN_WARNING "Error attempting compute root IV!\n");
		goto out;
	}
	#endif
	
	mutex_lock(&crypt_stat->cs_tfm_mutex);
	
	/*
	rc = wrapfs_assemble_cipher_name(&alg_name,"cbc");
	if(rc){
		goto out_unlock;
	}
	*/	
	crypt_stat->tfm = crypto_alloc_blkcipher("ctr(aes)",0,
						 CRYPTO_ALG_ASYNC);
	/*
	kfree(alg_name);
	*/
	if(IS_ERR(crypt_stat->tfm)){
		rc = PTR_ERR(crypt_stat->tfm);
		crypt_stat->tfm = NULL;
		printk(KERN_ERR "%s: Error initializing cipher\n",
		       __func__);
		goto out_unlock;
	}
	crypto_blkcipher_set_flags(crypt_stat->tfm,CRYPTO_TFM_REQ_WEAK_KEY);
	rc=0;
 out_unlock:
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
	goto out;
	
 out:
	return rc;
	
	
}

void wrapfs_destroy_crypt_stat(struct wrapfs_crypt_stat *crypt_stat)
{
	if(crypt_stat->tfm)
		crypto_free_blkcipher(crypt_stat->tfm);
	if(crypt_stat->hash_tfm)
		crypto_free_hash(crypt_stat->hash_tfm);

	memset(crypt_stat,0,sizeof(struct wrapfs_crypt_stat));
}



/*
  Returns zero on succes; negative on error
*/
int wrapfs_encrypt_page(struct page *page,struct page *lower_page)
{
	struct inode *upper_inode;
	int err =0;
	/*	
	char *enc_extent_virt;
	*/
	struct page *enc_extent_page = NULL;
	struct wrapfs_crypt_stat *crypt_stat = NULL;

	
	
	upper_inode = page->mapping->host;
	crypt_stat  = &(WRAPFS_SB(upper_inode->i_sb)->crypt_stat);
	/*
	printk(KERN_DEBUG "Entering page encryption routine\n");
	*/
	enc_extent_page = alloc_page(GFP_USER | __GFP_ZERO);
	if(!enc_extent_page){
		err = -ENOMEM;
		printk(KERN_ERR "%s: Error allocating memory for encryption\n",__func__);
		goto out;
	}
	/*
	enc_extent_virt = kmap(enc_extent_page);
	*/
	err = wrapfs_encrypt_extent(enc_extent_page,crypt_stat,page);
	if(err){
		printk(KERN_ERR "%s: Error encrypting extent! err =[%d]\n"
		       ,__func__,err);
		goto out;
	}
	
	if(lower_page != NULL){
		copy_highpage(lower_page,enc_extent_page);
		flush_dcache_page(lower_page);
		SetPageUptodate(lower_page);
		set_page_dirty(lower_page);
	}else {
		copy_highpage(page,enc_extent_page);
		flush_dcache_page(page);
		SetPageUptodate(page);
		set_page_dirty(page);
	}
	
	err =0;
 out:
	if(enc_extent_page){
		/*
		kunmap(enc_extent_page);
		*/
		__free_page(enc_extent_page);
	}
	return err;

}

int wrapfs_decrypt_page(struct page *page, struct file *lower_file)
{
	struct inode *upper_inode;
	struct page *dec_extent_page = NULL;
	struct wrapfs_crypt_stat *crypt_stat = NULL;
	char *dec_extent_virt;
	int rc =0;
	mm_segment_t old_fs;
	mode_t old_mode;
	loff_t offset =0;
	
	upper_inode = page->mapping->host;
	crypt_stat  = &(WRAPFS_SB(upper_inode->i_sb)->crypt_stat);
	printk(KERN_DEBUG "Entering page decryption routine\n");

	dec_extent_page = alloc_page(GFP_USER | __GFP_ZERO);
	if(!dec_extent_page){
		rc = -ENOMEM;
		printk(KERN_ERR "Error allocating memory for"
		       " Decrypted extent\n");
		goto out;
	}
	
	dec_extent_virt = (char*)kmap(dec_extent_page);
	
	offset = page_offset(page);
	printk(KERN_DEBUG "File offset is %lld\n",offset);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	old_mode = lower_file -> f_mode;
	lower_file -> f_mode |= FMODE_READ;
	rc = vfs_read(lower_file,dec_extent_virt,PAGE_CACHE_SIZE,
		      &offset);
	lower_file->f_mode = old_mode;
	set_fs(old_fs);
	printk(KERN_DEBUG "bytes readed is %d\n",rc);
	if(rc >=0 && rc < PAGE_CACHE_SIZE)
		memset(dec_extent_virt + rc, 0, PAGE_CACHE_SIZE -rc);
	
	if(rc <0){
		printk(KERN_ERR "Error reading lower page; rc = [%d]\n",rc);
		goto out;
	}
	kunmap(dec_extent_page);
	
	rc = wrapfs_decrypt_extent(page,crypt_stat,dec_extent_page);
	if(rc){
		printk(KERN_ERR "%s: Error decrypting, rc = [%d]\n",
		       __func__,rc);
		goto out;
	}
	

       

 out:
	if(dec_extent_page){
		
		__free_page(dec_extent_page);
	}
	return rc;
}


#ifdef EXTRA_CREDIT
/* 64 characters forming a 6-bit target field */
static unsigned char *portable_filename_chars = ("-.0123456789ABCD"
						 "EFGHIJKLMNOPQRST"
						 "UVWXYZabcdefghij"
						 "klmnopqrstuvwxyz");

/* We could either offset on every reverse map or just pad some 0x00's
 * at the front here */
static const unsigned char filename_rev_map[256] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 7 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 15 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 23 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 31 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 39 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 47 */
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, /* 55 */
	0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 63 */
	0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, /* 71 */
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, /* 79 */
	0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, /* 87 */
	0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, /* 95 */
	0x00, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, /* 103 */
	0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, /* 111 */
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, /* 119 */
	0x3D, 0x3E, 0x3F /* 123 - 255 initialized to 0x00 */
};

static int wrapfs_copy_filename(char **copied_name, size_t *copied_name_size,
				  const char *name, size_t name_size)
{
	int rc = 0;

	(*copied_name) = kmalloc((name_size + 1), GFP_KERNEL);
	if (!(*copied_name)) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy((void *)(*copied_name), (void *)name, name_size);
	(*copied_name)[(name_size)] = '\0';	/* Only for convenience
						 * in printing out the
						 * string in debug
						 * messages */
	(*copied_name_size) = name_size;
out:
	return rc;
}
static void
wrapfs_decode_from_filename(unsigned char *dst, size_t *dst_size,
			      const unsigned char *src, size_t src_size)
{
	u8 current_bit_offset = 0;
	size_t src_byte_offset = 0;
	size_t dst_byte_offset = 0;

	if (dst == NULL) {
		/* Not exact; conservatively long. Every block of 4
		 * encoded characters decodes into a block of 3
		 * decoded characters. This segment of code provides
		 * the caller with the maximum amount of allocated
		 * space that @dst will need to point to in a
		 * subsequent call. */
		(*dst_size) = (((src_size + 1) * 3) / 4);

		printk(KERN_DEBUG "dst_size is %d\n",*dst_size);
		goto out;
	}
	while (src_byte_offset < src_size) {
		unsigned char src_byte =
				filename_rev_map[(int)src[src_byte_offset]];

		switch (current_bit_offset) {
		case 0:
			dst[dst_byte_offset] = (src_byte << 2);
			current_bit_offset = 6;
			break;
		case 6:
			dst[dst_byte_offset++] |= (src_byte >> 4);
			dst[dst_byte_offset] = ((src_byte & 0xF)
						 << 4);
			current_bit_offset = 4;
			break;
		case 4:
			dst[dst_byte_offset++] |= (src_byte >> 2);
			dst[dst_byte_offset] = (src_byte << 6);
			current_bit_offset = 2;
			break;
		case 2:
			dst[dst_byte_offset++] |= (src_byte);
			dst[dst_byte_offset] = 0;
			current_bit_offset = 0;
			break;
		}
		src_byte_offset++;
	}
	(*dst_size) = dst_byte_offset;
out:
	return;
}

void wrapfs_encode_for_filename(unsigned char *dst, size_t *dst_size,
				  unsigned char *src, size_t src_size)
{
	size_t num_blocks;
	size_t block_num = 0;
	size_t dst_offset = 0;
	unsigned char last_block[3];

	if (src_size == 0) {
		(*dst_size) = 0;
		goto out;
	}
	num_blocks = (src_size / 3);
	if ((src_size % 3) == 0) {
		memcpy(last_block, (&src[src_size - 3]), 3);
	} else {
		num_blocks++;
		last_block[2] = 0x00;
		switch (src_size % 3) {
		case 1:
			last_block[0] = src[src_size - 1];
			last_block[1] = 0x00;
			break;
		case 2:
			last_block[0] = src[src_size - 2];
			last_block[1] = src[src_size - 1];
		}
	}
	(*dst_size) = (num_blocks * 4);
	if (!dst)
		goto out;
	while (block_num < num_blocks) {
		unsigned char *src_block;
		unsigned char dst_block[4];

		if (block_num == (num_blocks - 1))
			src_block = last_block;
		else
			src_block = &src[block_num * 3];
		dst_block[0] = ((src_block[0] >> 2) & 0x3F);
		dst_block[1] = (((src_block[0] << 4) & 0x30)
				| ((src_block[1] >> 4) & 0x0F));
		dst_block[2] = (((src_block[1] << 2) & 0x3C)
				| ((src_block[2] >> 6) & 0x03));
		dst_block[3] = (src_block[2] & 0x3F);
		dst[dst_offset++] = portable_filename_chars[dst_block[0]];
		dst[dst_offset++] = portable_filename_chars[dst_block[1]];
		dst[dst_offset++] = portable_filename_chars[dst_block[2]];
		dst[dst_offset++] = portable_filename_chars[dst_block[3]];
		block_num++;
	}
out:
	return;
}
static int wrapfs_decrypt_filename(char **dec_file_name,
				size_t *filename_size,
				struct wrapfs_crypt_stat *crypt_stat,
				char *enc_file_name,
				int enc_len)
{
	int rc =0;
	unsigned char* iv = (unsigned char*)aes_iv;
	struct blkcipher_desc desc = {
		.tfm = crypt_stat->tfm,
		.info = iv,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};

	
	struct scatterlist dst_sg;
	struct scatterlist src_sg;
	
	
	sg_init_table(&src_sg,1);
	sg_init_table(&dst_sg,1);
	sg_set_buf(&src_sg,enc_file_name,enc_len);
	sg_set_buf(&dst_sg,*dec_file_name,enc_len);
	UDBG;
	mutex_lock(&crypt_stat->cs_tfm_mutex);
	rc =crypto_blkcipher_setkey(crypt_stat->tfm,crypt_stat->key,
				crypt_stat->key_size);

	if(rc){
		printk(KERN_ERR "Error setting key for filename decryption\n");
		mutex_unlock(&crypt_stat->cs_tfm_mutex);
		rc = -EINVAL;
		goto out;
	}

        crypto_blkcipher_decrypt_iv(&desc,&dst_sg,&src_sg,enc_len);
	*filename_size = enc_len;
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
 out :
	return rc;
}

static int wrapfs_encr_filename(char *enc_file_name,
				struct wrapfs_crypt_stat *crypt_stat,
				char *file_name,
				int len)
{
	int rc =0;
	unsigned char* iv = (unsigned char*)aes_iv;
	struct blkcipher_desc desc = {
		.tfm = crypt_stat->tfm,
		.info = iv,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	struct scatterlist dst_sg;
	struct scatterlist src_sg;
	sg_init_table(&src_sg,1);
	sg_init_table(&dst_sg,1);
	sg_set_buf(&src_sg,file_name,len);
	sg_set_buf(&dst_sg,enc_file_name,len);

	mutex_lock(&crypt_stat->cs_tfm_mutex);
	rc =crypto_blkcipher_setkey(crypt_stat->tfm,crypt_stat->key,
				crypt_stat->key_size);

	if(rc){
		printk(KERN_ERR "Error setting key for filename decryption\n");
		mutex_unlock(&crypt_stat->cs_tfm_mutex);
		rc = -EINVAL;
		goto out;
	}

        crypto_blkcipher_encrypt_iv(&desc,&dst_sg,&src_sg,len);
	
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
 out :
	return rc;
}

static int
wrapfs_encrypt_filename(struct wrapfs_filename *filename,
			struct wrapfs_crypt_stat *crypt_stat )
{
	int rc = 0;
	
	filename->encrypted_filename_size = filename->filename_size;
	filename->encrypted_filename = kmalloc(
				       filename->encrypted_filename_size,
				       GFP_KERNEL);
	if(!filename->encrypted_filename){
		printk(KERN_ERR "%s: Out of mem when allocating space "
		       "for encrypting filename\n",__func__);
		rc= -ENOMEM;
		goto out;
	}
	
	if(crypt_stat){
		rc = wrapfs_encr_filename(filename->encrypted_filename,
					  crypt_stat,
					  filename->filename,
					  filename->filename_size);
		if(rc){
			printk(KERN_ERR "%s: Error generating MD5"
			       " for encrypting filename\n",__func__);
			filename->encrypted_filename_size =0;
			kfree(filename->encrypted_filename);
			filename->encrypted_filename = NULL;
			goto out;
		}
	}

 out:
	return rc;
}

int wrapfs_encrypt_encode_filename(char **encoded_name,
				   size_t *encoded_name_size,
				   struct wrapfs_crypt_stat *crypt_stat,
				   const char *name, size_t name_size)
{
	size_t encoded_name_no_prefix_size;
	int rc =0;
	(*encoded_name) = NULL;
	(*encoded_name_size) =0;
	
	if(crypt_stat){
		struct wrapfs_filename *filename;
		filename = kzalloc(sizeof(*filename),GFP_KERNEL);
		if(!filename){
			printk(KERN_ERR "%s: No Mem when kzalloc\n",
			       __func__);
			rc = -ENOMEM;
			goto out;
		}
	
		filename->filename = (char*)name;
		filename->filename_size = name_size;
		rc = wrapfs_encrypt_filename(filename,crypt_stat);
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to encrypt "
			       "filename; rc = [%d]\n", __func__, rc);
			kfree(filename);
			goto out;
		}
	
		wrapfs_encode_for_filename(
			NULL, &encoded_name_no_prefix_size,
			filename->encrypted_filename,
			filename->encrypted_filename_size);
		(*encoded_name_size) = WRAPFS_FILENAME_PREFIX_SIZE +
			encoded_name_no_prefix_size;
		(*encoded_name) = kmalloc((*encoded_name_size) +1,GFP_KERNEL);

	        if (!(*encoded_name)) {
			printk(KERN_ERR "%s: Out of memory whilst attempting "
			       "to kzalloc [%zd] bytes\n", __func__,
			       (*encoded_name_size));
			rc = -ENOMEM;
			kfree(filename->encrypted_filename);
			kfree(filename);
			goto out;
		}

		memcpy((*encoded_name),
		       WRAPFS_FILENAME_PREFIX,
		       WRAPFS_FILENAME_PREFIX_SIZE);
		wrapfs_encode_for_filename(
			(*encoded_name)+WRAPFS_FILENAME_PREFIX_SIZE,
			&encoded_name_no_prefix_size,
			filename->encrypted_filename,
			filename->encrypted_filename_size);
		
		(*encoded_name_size) =
				(WRAPFS_FILENAME_PREFIX_SIZE
				 + encoded_name_no_prefix_size);
		(*encoded_name)[(*encoded_name_size)] = '\0';

		if(rc){
			printk(KERN_ERR "%s: Error attempting to encode "
		       "encrypted filename; rc = [%d]\n", __func__,
		       rc);
			kfree((*encoded_name));
			(*encoded_name) = NULL;
			(*encoded_name_size) = 0;
		}
		kfree(filename->encrypted_filename);
		kfree(filename);
	} else {
		rc = wrapfs_copy_filename(encoded_name,
					    encoded_name_size, 
					    name, name_size);
	}
		
 out: 
	return rc;
            
}


int wrapfs_decode_and_decrypt_filename(char **plaintext_name,
					 size_t *plaintext_name_size,
					 struct dentry *wrapfs_dir_dentry,
					 const char *name, size_t name_size)
{
	struct wrapfs_crypt_stat *crypt_stat = 
		&(WRAPFS_SB(wrapfs_dir_dentry->d_sb)->crypt_stat);
	char *decoded_name;
	size_t decoded_name_size =0;
	int rc = 0;

	const char *orig_name = name;
	size_t orig_name_size = name_size;

	printk(KERN_DEBUG "names_size is %d\n", name_size);
	if(name_size > WRAPFS_FILENAME_PREFIX_SIZE){
		name += WRAPFS_FILENAME_PREFIX_SIZE;
	        name_size -= WRAPFS_FILENAME_PREFIX_SIZE;
	}
	else{
		return rc;
	}
	wrapfs_decode_from_filename(NULL,&decoded_name_size,
				    name, name_size);
	decoded_name = kmalloc(decoded_name_size, GFP_KERNEL);
       	if (!decoded_name) {
     		printk(KERN_ERR "%s: Out of memory whilst attempting "
	  	       "to kmalloc [%zd] bytes\n", __func__,
		       decoded_name_size);
		rc = -ENOMEM;
	 	goto out;
	}
	printk("REACH HERE!\n");
	wrapfs_decode_from_filename(decoded_name,&decoded_name_size,
				    name, name_size);
	wrapfs_decrypt_filename(plaintext_name,
				plaintext_name_size,
				crypt_stat,
				decoded_name,decoded_name_size);
	if(rc){
		rc = wrapfs_copy_filename(plaintext_name,
					    plaintext_name_size,
				     	    orig_name, orig_name_size);
		goto out_free;
	}
	
 out_free:
	kfree(decoded_name);
 out:
	return rc;
}
#endif 
