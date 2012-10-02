#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h>
#include <linux/dcache.h>
#include <linux/security.h>

#include "xcrypt_common.h"
#include "xcrypt_fun.h"

extern asmlinkage long(*STUB_wrapper_syscall) (void __user *args);

int xcrypt_read_write(struct file* infile,struct file* outfile,void *buf,void *keybuf,size_t key_len,int flags)
{
	struct inode *inode_in = infile->f_dentry->d_inode;
	loff_t infile_size = i_size_read(inode_in);
	size_t bytes_one_run = xcrypt_chunk_size;
        size_t  remaining_bytes = 0;
        size_t out_len =0;
	
		                                                  
	int err =0;
	//If decrypting, we need round to multiple of 16  per page due to the padding
	if(!flags)
		bytes_one_run += 16-( bytes_one_run & 0x0f );
	
	out_len = bytes_one_run;

   	if(flags){
		BUG_ON((infile->f_pos)!=0);
	}else {
		BUG_ON((outfile->f_pos)!=0);
	}

	
        printk("infile size is %lld\n",infile_size);
	/*NULL file*/
	if(infile_size == 0 || (!flags && infile_size == 64))
		return 0;
	
        while(infile->f_pos+bytes_one_run < infile_size){
	    
		err = infile->f_op->read(infile,(char *)buf,bytes_one_run,&infile->f_pos);
		if(err <0){
			printk(KERN_ERR "read failure processing infile!\n");
			return -EIO;
		}
		if(flags){
			err = encrypt_buffer(buf,bytes_one_run,buf,&out_len,keybuf,key_len);

			
		} else {
			
			
		        err = decrypt_buffer(buf,bytes_one_run,buf,&out_len,keybuf,key_len);
			
		}
		if(err<0){
			if(flags){
				printk(KERN_ERR "Encryption failure!\n");
			}else {
				printk(KERN_ERR "Decryption failure!\n");
			}
			return -EMEDIUMTYPE;
		}
					
		err = outfile->f_op->write(outfile,(char *)buf,out_len,
					  &outfile->f_pos);
		if(err<0){
			printk(KERN_ERR "write outfile failure,Abort!\n");
			return -EIO;
		}
		
		
	}
	
	remaining_bytes  = infile_size - infile->f_pos;
	err = infile->f_op->read(infile,(char *)buf,remaining_bytes,&infile->f_pos);
	if(err < 0){
		return -EIO;
	}
       	if(flags){
		err = encrypt_buffer(buf,remaining_bytes,buf,&out_len,keybuf,key_len);
	} else {
		
		err= decrypt_buffer(buf,remaining_bytes,buf,&out_len,keybuf,key_len);
		
	}
	
	if(err<0)
		return -EMEDIUMTYPE;
	err = outfile->f_op->write(outfile,(char *)buf,out_len,&outfile->f_pos);
	if(err <0){
		printk(KERN_ERR "Padding error!!!\n");
		return -EMEDIUMTYPE;
	}
	
      
	/*Judge if file size is correct*/
	/*
	printk(KERN_DEBUG "File size is %lld, f_pos is now %lld\n,remaining bytes is %d",origin_file_size,outfile->f_pos,
	       remaining_bytes);
	*/
	if(!flags && outfile->f_pos != origin_file_size){
		printk(KERN_ALERT "File size is not correct, input file may be corrupted!\n");
		return -EFBIG;
	}
	return 0;

}
int xcrypt_gen_MD5(char *src,char *dst,size_t len)
{
	int err =0;
	struct scatterlist sg;
       
	struct hash_desc desc = {
		.tfm   = NULL,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	sg_init_one(&sg, (u8*)src,len);
	
	desc.tfm = crypto_alloc_hash("md5",0,CRYPTO_ALG_ASYNC);
	if(!(desc.tfm)||IS_ERR(desc.tfm)){
		err = -PTR_ERR(desc.tfm);
		printk(KERN_ERR "Allocate crypto context fail!\n");
		goto out;
	}
	err = crypto_hash_init(&desc);
	if(err){
		printk(KERN_ERR "Error init hash\n");
		goto out;
	}
	err = crypto_hash_update(&desc,&sg,len);
	if(err){
		printk(KERN_ERR "Error update hash\n");
		goto out;
	}
	err = crypto_hash_final(&desc,dst);
	if(err){
		printk(KERN_ERR "Error finalizing hash!\n ");
		goto out;
	}
		
 out:
	
	return err;
}

int xcrypt_add_metadata(struct file *infile, struct file* outfile,void *iv,void *keybuf,size_t key_len)
{
	struct inode *inode_in = infile->f_dentry->d_inode;
	loff_t infile_size = i_size_read(inode_in);
	int err =0;
	
	int checksum_len =16;
	char *checksum = kzalloc(checksum_len,GFP_KERNEL);
	char *cipher_alg_checksum = kzalloc(checksum_len,GFP_KERNEL);

	if(IS_ERR(checksum)){
		err = -PTR_ERR(checksum);
		goto out;
	}
	
	if(IS_ERR(cipher_alg_checksum)){
		err = -PTR_ERR(cipher_alg_checksum);
		goto out;
	}
	err = outfile->f_op->write(outfile,(char*)&infile_size,sizeof(loff_t),&outfile->f_pos);
	if(err <0){
		goto out;
	}
	printk("IV IS %s\n",(char*)iv);
	
	err = outfile->f_op->write(outfile,(char*)iv,IV_LEN,&outfile->f_pos);
	if(err <0){
		goto out;
	}

	/*write keylen and encryption chunck size to preamble*/

	err = xcrypt_gen_MD5((char*)keybuf,checksum,key_len);
	if(err <0){
		printk(KERN_ERR "MD5 hash error!\n");
		goto out;
	}
	err = xcrypt_gen_MD5(blkcipher_alg,cipher_alg_checksum,strlen(blkcipher_alg)+1);
	if(err<0){
		printk(KERN_ERR "MD5 cipher name hash error\n");
		goto out;
	}
	err = outfile->f_op->write(outfile,checksum,checksum_len,&outfile->f_pos);
	if(err <0){
		printk("write output file error!\n");
		goto out;
	}
	

	err = outfile->f_op->write(outfile,(char*)&key_len,sizeof(size_t),&outfile->f_pos);
	if(err <0){
		printk(KERN_ERR "Write keylen info to preamble failed!\n");
		goto out;
	}
	err = outfile->f_op->write(outfile,(char*)&xcrypt_chunk_size,sizeof(int),&outfile->f_pos);
	if(err <0){
		printk(KERN_ERR "Write encryption chunck size info to preamble failed!\n");
		goto out;
	}
	err = outfile->f_op->write(outfile,cipher_alg_checksum,checksum_len,&outfile->f_pos);
	if(err<0){
		printk(KERN_ERR "Write cipher algorithm name hash to preamble failed!\n");
		goto out;
	}
	
	BUG_ON(outfile->f_pos >(sizeof(size_t)+sizeof(int)+ checksum_len +sizeof(loff_t)+IV_LEN)+
	       checksum_len);
	outfile->f_pos = PREAMBLE_LEN;
	
 out:
	if(checksum)
		kfree(checksum);
	if(cipher_alg_checksum)
		kfree(cipher_alg_checksum);
	if(err >0)
		err =0;
	return err;
	
}

int xcrypt_verify_metadata(struct file *infile,void *iv,void *keybuf,size_t key_len)
{
        loff_t infile_size = 0;
	int err =0;
	int test =0;
	int checksum_len  =16;
	
        
        char *checksum = kzalloc(checksum_len,GFP_KERNEL);
	char *incoming_checksum = kzalloc(checksum_len,GFP_KERNEL);
        char *cipher_checksum   = kzalloc(checksum_len,GFP_KERNEL);
	char *incoming_cipher_checksum = kzalloc(checksum_len,GFP_KERNEL);
	int incoming_keylen = 0;
	
	if(IS_ERR(checksum)){
		err = -PTR_ERR(checksum);
		goto out;
	}
	
	if(IS_ERR(incoming_checksum)){
		err = -PTR_ERR(incoming_checksum);
		goto out;
	}
	if(IS_ERR(cipher_checksum)){
		err = -PTR_ERR(cipher_checksum);
		goto out;
	}
	
	if(IS_ERR(incoming_cipher_checksum)){
		err = -PTR_ERR(incoming_cipher_checksum);
		goto out;
	}

	err = xcrypt_gen_MD5((char*)keybuf,checksum,key_len);
	if(err <0){
		printk(KERN_ERR "MD5 hash error!\n");
		goto out;
	}
	err = xcrypt_gen_MD5(blkcipher_alg,cipher_checksum,strlen(blkcipher_alg)+1);
	if(err<0){
		printk(KERN_ERR "Cipher alg naem hash error!\n");
		goto out;
	}
	err = infile->f_op->read(infile,(char*)&infile_size,sizeof(loff_t),&infile->f_pos);
	if(err <0){
		printk(KERN_ERR "Infile size length read failure!\n");
		goto out;
	}
	origin_file_size = infile_size;
        err = infile->f_op->read(infile,(char*)iv,IV_LEN,&infile->f_pos);
	if(err <0){
		printk(KERN_ERR "Read IV error!\n");
		goto out;
	}
	
	
	err = infile->f_op->read(infile,incoming_checksum,checksum_len,&infile->f_pos);
	if(err <0){
		printk(KERN_ERR "Read checksum IO error!\n");
		goto out;
	}
	if((test = memcmp((void *)incoming_checksum,(void *)checksum,checksum_len))!=0){
		err = -EKEYREJECTED;
		printk(KERN_ALERT "Checksum verification failure, file may got corrupted!\n");
		goto out;
	}
	err = infile->f_op->read(infile,(char*)&incoming_keylen,sizeof(size_t),&infile->f_pos);
	if(err<0){
		printk(KERN_ERR "Read key len error!\n");
		goto out;
	}
	if(incoming_keylen != key_len){
		err= -EKEYREJECTED;
		printk(KERN_ALERT "Key length used does not match original key length!\n");
		goto out;
	}
	err = infile->f_op->read(infile,(char*)&xcrypt_chunk_size,sizeof(int),&infile->f_pos);
	if(err <0){
		printk(KERN_ERR "Read ecrypting chunk size fail.\n");
		goto out;		
	}
        
	err = infile->f_op->read(infile,incoming_cipher_checksum,checksum_len,&infile->f_pos);
	if(err < 0){
		printk(KERN_ERR "Read cipher alg checksum fail!\n");
		goto out;
	}
	if((test= memcmp((void*)incoming_cipher_checksum,(void*)cipher_checksum,checksum_len))!=0){
		err = -EMEDIUMTYPE;
		printk("Checksum for cipher alg name matching failure!\n");
		goto out;
	}/*
       	printk(KERN_DEBUG "key_len is %d,file_pos now isOB %lld,test is %d",key_len,infile->f_pos,test);
	*/
	if(infile->f_pos != (8+IV_LEN +checksum_len+ checksum_len+sizeof(size_t)+sizeof(int))){
		err = -1;
		goto out;
	}
		
	
	infile->f_pos=PREAMBLE_LEN;
	
 out:
	if(checksum)
		kfree(checksum);
	if(incoming_checksum)
		kfree(incoming_checksum);
	if(incoming_cipher_checksum)
		kfree(incoming_cipher_checksum);
	if(cipher_checksum)
		kfree(cipher_checksum);
	
	if(err >0)
		err =0;
	return err;
}
static int partial_file_cleanup(struct file* fp)
{
	int err =0;
	struct dentry *fp_dentry = fp->f_dentry;
	struct inode  *fp_dir_inode = fp_dentry->d_parent->d_inode;
        struct dentry *parent_dir_dentry = NULL;

	dget(fp_dentry);
	parent_dir_dentry = dget_parent(fp_dentry);
	mutex_lock_nested(&(parent_dir_dentry->d_inode->i_mutex),
			  I_MUTEX_PARENT);
	
	err = vfs_unlink(fp_dir_inode,fp_dentry);
	if(err){
		printk(KERN_ERR "ERROR in vfs_unlink! Errcode is %d\n",err);
		goto release_lock;
	}
	       
 release_lock:
	mutex_unlock(&(parent_dir_dentry->d_inode->i_mutex));
	dput(parent_dir_dentry);
	dput(fp_dentry);
      	
	return err;
}
/*return 0 if regular*/
static inline int check_reg(struct file* fp)
{
	struct inode *fp_inode = fp->f_dentry->d_inode;
	return !S_ISREG(fp_inode->i_mode);
}

static inline int check_eq_file(struct file* fp_in,struct file* fp_out)
{
	struct inode *inode_in = fp_in->f_dentry->d_inode;
	struct inode *inode_out = fp_out->f_dentry->d_inode;

	return ((inode_in->i_ino == inode_out->i_ino)&&
		(inode_in->i_sb->s_bdev == inode_out->i_sb->s_bdev));
}
asmlinkage long my_sys_xcrypt(void __user *args)
{

	struct xcrypt_args *user_args = NULL;
	
	/* use getname below*/
	
	
	char *infile_name = NULL;
	char *outfile_name =NULL;
	
	struct file *filp_in = NULL;
	
	struct file *filp_out = NULL;
	loff_t infile_size;
        
	/* use size_t, may not be enough*/
	char *kbuf = NULL;
	char *tmp_buf = NULL;
       	
	int tmp_buf_len = PAGE_CACHE_SIZE;
	int alg_namelen =0 ; 
	int bytes = 0;
	size_t key_len; /*copied;*/
	size_t pad_size = 16;
	int err =0;
	int flags =0;
	mm_segment_t old_fs;
	
	
	infile_size =0;
        origin_file_size =0;


	user_args = kmalloc(sizeof(struct xcrypt_args),GFP_KERNEL);
	if(IS_ERR(user_args)){
		err = -PTR_ERR(user_args);
		goto out_kfree;
	}

	err = copy_from_user(user_args,(struct xcrypt_args *)args,
	  		     sizeof(struct xcrypt_args));
	if(err){
		err = -EFAULT;
		goto out_kfree;
	}

      	#ifdef EXTRA_CREDIT
       
	        xcrypt_chunk_size = user_args->blk_size;
		
		alg_namelen = strlen_user(user_args->cipher_alg)+1;
		blkcipher_alg = kmalloc(alg_namelen,GFP_KERNEL);
		if(IS_ERR(blkcipher_alg)){
			err = -PTR_ERR(blkcipher_alg);
			goto out_kfree;
		}
		err = copy_from_user(blkcipher_alg,user_args->cipher_alg,alg_namelen);
		
		if(err){
			err = -EFAULT;
			goto out_kfree;
		}
        
       #endif

        tmp_buf_len = xcrypt_chunk_size+pad_size -(xcrypt_chunk_size & (pad_size-1)) ;       
	tmp_buf = kzalloc(tmp_buf_len ,GFP_KERNEL);
	if(!tmp_buf || IS_ERR(tmp_buf)){
	        err = -PTR_ERR(tmp_buf);
		goto out_kfree;
	}
	infile_name = getname(user_args->infile);
	if(IS_ERR(infile_name)){
		err = -PTR_ERR(infile_name);
		goto out_kfree;
	}
	outfile_name = getname(user_args->outfile);
	if(IS_ERR(outfile_name)){
		err = -PTR_ERR(outfile_name);
		goto out_kfree;
	}

	
	key_len = user_args->keylen;
	flags   = user_args->flags;
        
	printk(KERN_DEBUG "infile_name is %s\n",infile_name);
	printk(KERN_DEBUG "outfile name is %s\n",outfile_name);
	printk(KERN_DEBUG "keybuf len is %d\n",key_len);
	/*allocate kernel mem and copy keybuf over*/
	kbuf = kmalloc(key_len,GFP_KERNEL);
        if(IS_ERR(kbuf))
	{
		err = -PTR_ERR(kbuf);
		goto out_kfree;
	}
	err = copy_from_user(kbuf,(char*)user_args->keybuf,key_len);
	if(err){
		err = -EFAULT;
		goto out_kfree;
	
	}/*Open infile inside kernel*/
	
	
	filp_in = filp_open(infile_name,O_RDONLY,0);
	
	putname(infile_name);
	if(!filp_in || IS_ERR(filp_in)){
		printk(KERN_ALERT "Xcrypt syscall infile open failure\n");
		err = -ENOENT; /* -ENOENT*/
		goto out_kfree;
	}
	

	err = check_reg(filp_in);
	if(err){
		printk(KERN_ALERT "Input file is not regular!\n");
		err = -EISDIR;
		goto out_FILE_CLEANUP;
	}
	filp_out = filp_open(outfile_name,O_WRONLY |O_TRUNC | O_CREAT,filp_in->f_mode);
	
	putname(outfile_name);
	if(!filp_out || IS_ERR(filp_out)){
		printk(KERN_ALERT "Xcrypt syscall outfile open failure\n");
		err = -PTR_ERR(filp_out);
		goto out_OPEN_FAIL;
	}
	if(check_eq_file(filp_in,filp_out)){
		printk(KERN_ALERT "Input and output file are the same!\n");
		err = -EINVAL;
		goto out_kfree;
	}
	old_fs = get_fs();
	set_fs(get_ds());
	
	/*check if underlying fs does allow read
	 */
	if(!filp_in->f_op || !filp_in->f_op->read){
		err = -EPERM;
		goto out_NO_READ_FS;
	}
        
        if(!filp_out->f_op || !filp_out->f_op->write){
		err = -EROFS;
		goto out_NO_WRITE_FS;
	}
	
	filp_in->f_pos = 0;
        filp_out->f_pos = 0;
	
	/*init iv */
             
        if(flags & 0x01){
		/*Encrpting, we init iv */
		
		err = init_iv(aes_iv,filp_in,tmp_buf);
		
		if(err <0){
			err = -EFAULT;
			goto out_IV_INIT_ERR;
		}
	} else {
		/*Decrypting, read from file*/
		memset(aes_iv,0,IV_LEN);
	}
	if(flags & 0x01){
		err = xcrypt_add_metadata(filp_in,filp_out,aes_iv,kbuf,key_len);
		if(err <0)
			goto out_READ_FAIL;
	} else {
		err = xcrypt_verify_metadata(filp_in,aes_iv,kbuf,key_len);
		 
		if(err<0){
			
			printk(KERN_DEBUG "err after verify is %d\n",err);
			
			goto out_READ_FAIL;
		}
	}
	
					     
        
	bytes = xcrypt_read_write(filp_in,filp_out,tmp_buf,kbuf,key_len,flags & 0x01);
	if(bytes < 0){
		
		err = bytes;
		set_fs(old_fs);
		goto out_FILE_CLEANUP;
	}
     
	/*printk(KERN_DEBUG "read string: %s\n ",tmp_buf);
	 */
	
	set_fs(old_fs);
out_IV_INIT_ERR:
out_READ_FAIL:
out_OPEN_FAIL:
out_NO_READ_FS:
out_NO_WRITE_FS:
out_FILE_CLEANUP:
	
	
	if(filp_in)
		filp_close(filp_in,NULL);
	if(filp_out){
		if(err <0){
			if(partial_file_cleanup(filp_out)){
				err = -EUCLEAN;
			}
		}
		filp_close(filp_out,NULL);
		
	}
out_kfree:

	#ifdef EXTRA_CREDIT	
		if(blkcipher_alg)
			kfree(blkcipher_alg);
        #endif
        if(tmp_buf)
		kfree(tmp_buf);
	if(kbuf)
		kfree(kbuf);
	kfree(user_args);	
       
	if(IS_ERR(infile_name))
		putname(infile_name);
        if(IS_ERR(outfile_name))
		putname(outfile_name);
	printk(KERN_DEBUG "FREE FINISH!\n ");
      
	return err;
}

static int __init init_xcrypt(void)
{
	printk(KERN_DEBUG "THIS IS FOR EXTRA_CREDIT DEBUG!!!!\n");
	STUB_wrapper_syscall = (void*)(my_sys_xcrypt);
       
	return 0;
}
static void __exit exit_xcrypt(void)
{
	if(STUB_wrapper_syscall == (void*)my_sys_xcrypt)
		STUB_wrapper_syscall = NULL;
	else
		printk(KERN_ALERT "MODULE SHOULD NOT BE INITIALIZED\n");
}

MODULE_AUTHOR("Chenyang Liu, CSE506 hw1 ,Stony Brook University");
MODULE_DESCRIPTION("TEST for xcrypt syscall");

MODULE_LICENSE("GPL");

module_init(init_xcrypt);
module_exit(exit_xcrypt);
