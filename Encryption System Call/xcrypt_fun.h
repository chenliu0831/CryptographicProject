#ifndef _XCRYPT_FUN
#define _XCRYPT_FUN

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include "xcrypt_common.h"

static  char *blkcipher_alg = "cbc(aes)";


static int xcrypt_chunk_size = PAGE_CACHE_SIZE; 

static size_t ivsize;
static loff_t origin_file_size = 0;

#define PREAMBLE_LEN PAGE_CACHE_SIZE
#define MY_IV "lcylcylcylcylvyj"
#define IV_LEN 16

static  char *aes_iv = (char *)MY_IV;


int encrypt_buffer( void *in, size_t in_len,
		       void *out, size_t *out_len,
		       const void *key, size_t keylen)
{
	int retval = 0;
	struct crypto_blkcipher *tfm =  crypto_alloc_blkcipher(blkcipher_alg,
	       						   0,CRYPTO_ALG_ASYNC);
	struct scatterlist sg_in[2],sg_out[1];
	struct blkcipher_desc desc  = {.tfm = tfm, .flags = 0};
	
	
	char pad[16];
	void * iv = NULL;
	size_t zero_padding = 16-(in_len & 0x0f);
	
       
	if(IS_ERR(tfm))
		return PTR_ERR(tfm);
	
	memset(pad,zero_padding,zero_padding);
	*out_len = in_len + zero_padding;
	
	crypto_blkcipher_setkey((void*)tfm,key,keylen);
	
		
	sg_init_table(sg_in,2);
	sg_set_buf(&sg_in[0],in,in_len);
	sg_set_buf(&sg_in[1],pad,zero_padding);
	sg_init_table(sg_out,1);
	sg_set_buf(sg_out,out,*out_len);

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	
	memcpy(iv,aes_iv,ivsize);

	retval = crypto_blkcipher_encrypt(&desc,sg_out,sg_in,
					  in_len + zero_padding);
	crypto_free_blkcipher(tfm);
	if(retval < 0 )
		printk(KERN_ERR "aes_encrypt fail!\n");

        if(retval >0)
		retval =0;
	return retval;
	
}

int decrypt_buffer( void *in, size_t in_len,
		    void *out, size_t *out_len,
		    const void *key, size_t keylen)
{
	int retval = 0;
	struct crypto_blkcipher *tfm =  crypto_alloc_blkcipher(blkcipher_alg,
	       						   0,CRYPTO_ALG_ASYNC);
	struct scatterlist sg_in[1],sg_out[2];
	struct blkcipher_desc desc  = {.tfm = tfm, .flags = 0};
	
	int ivsize;
	int lsb =0;
	char pad[16];
	void * iv = NULL;
	
	if(IS_ERR(tfm))
		return PTR_ERR(tfm);
	
	
	crypto_blkcipher_setkey((void*)tfm,key,keylen);
	
		
	sg_init_table(sg_in,1);
	sg_set_buf(sg_in,in,in_len);
	sg_init_table(sg_out,2);
	sg_set_buf(&sg_out[0],out,*out_len);
	sg_set_buf(&sg_out[1],pad,sizeof(pad));

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	
	memcpy(iv,aes_iv,ivsize);
	
	retval = crypto_blkcipher_decrypt(&desc,sg_out,sg_in,
					  in_len);
	crypto_free_blkcipher(tfm);
	if(retval < 0 ){
		printk(KERN_ERR "aes decryption fail!\n");
		goto out;
	}
	/*
	printk(KERN_DEBUG "in_len is %d, out_len is %d,lsb is %d\n",in_len,*out_len,lsb);
	*/
	if(in_len <= *out_len){
		lsb = ((char*)out)[in_len-1];
	}else {
		lsb = pad[in_len - *out_len -1];
	}
	if(lsb <=16 && in_len >= lsb){
       		*out_len = in_len - lsb;
	} else {
	       	printk(KERN_ERR "BAD PADDING %d on src!!\n",lsb);
	       	retval = -EPERM;
	       	goto out;
	}
	
	
        if(retval >0)
		retval =0;
 out:	
	return retval;
	
}
int init_iv(char *iv,struct file *infile,char *tmp_buf)
{
	
	#ifdef EXTRA_CREDIT
	
	struct inode *inode_in = infile->f_dentry->d_inode;
        unsigned long page_idx = (unsigned long)tmp_buf & ~(PAGE_CACHE_SIZE-1);
	unsigned long inode_num = inode_in -> i_ino;
	
	memcpy(iv,&page_idx,sizeof(unsigned long));
	memcpy(iv+sizeof(unsigned long),&inode_num,sizeof(unsigned long));
	if(IS_ERR(iv))
		return -1;
	return 0;
	#else
	/* use predefined aes_iv*/
	return 0;
	#endif
	
}
#endif
