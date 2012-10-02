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

#include "wrapfs.h"
struct page *wrapfs_get_locked_page(struct inode *inode,loff_t index)
{
	struct page *page = read_mapping_page(inode->i_mapping, index,NULL);
	if(!IS_ERR(page))
		lock_page(page);
	return page;
}
static int fill_zero_to_eofpage(struct page *page, unsigned int to)
{
	struct inode *inode = page->mapping->host;
	int end_byte_in_page;

	if ((i_size_read(inode) / PAGE_CACHE_SIZE) != page->index)
		goto out;
	end_byte_in_page = i_size_read(inode) % PAGE_CACHE_SIZE;
	if (to > end_byte_in_page)
		end_byte_in_page = to;
	zero_user_segment(page, end_byte_in_page, PAGE_CACHE_SIZE);
out:
	return 0;
}
static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

	
	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;
	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	return err;
}
/*
 * wrapfs_writepage
 * @page is already locked?
 * 0 on success; non-zero otherwise
 */
static int wrapfs_writepage(struct page *page,struct writeback_control *wbc)
{
	int rc = -EIO;
	struct inode *inode;
	struct inode *lower_inode;
	struct page *lower_page;
	struct address_space *lower_mapping; /*lower inode mapping*/
	
	gfp_t mask;
	#ifdef WRAPFS_CRYPTO
	struct wrapfs_crypt_stat *crypt_stat;
	BUG_ON(use_mmap==0);
	#endif
	/*
        printk(KERN_DEBUG "Entering writepage\n");
	*/
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG;
#endif
	if(current->flags & PF_MEMALLOC){
		redirty_page_for_writepage(wbc,page);
		rc =0;
		goto out;
	}
	inode = page->mapping->host;
	
	if(!inode || !WRAPFS_I(inode) || !WRAPFS_I(inode)->lower_inode){
		rc = 0;
		goto out;
	}
	#ifdef WRAPFS_CRYPTO
	crypt_stat = &WRAPFS_SB(inode->i_sb)->crypt_stat;
	if(crypt_stat->flags & WRAPFS_KEY_NULL){
		printk(KERN_DEBUG "KEY is not set! Abort!\n");
		rc = -ENOENT;
		goto out;
	}
	#endif
	lower_inode = wrapfs_lower_inode(inode);
	lower_mapping = lower_inode->i_mapping;
	
	mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
	lower_page = find_or_create_page(lower_mapping,page->index,mask);
	if(!lower_page) {
		rc =0;
		set_page_dirty(page);
		goto out;
	}
	/* may be some alternatives here*/
	#ifdef WRAPFS_CRYPTO
	rc = wrapfs_encrypt_page(page,lower_page);
	if(rc){
		printk(KERN_DEBUG "%s: Encryption page and"
		       " copy to lower failed,return %d",
		       __func__,rc);
		ClearPageUptodate(page);
		goto out_release;
	}
	#else	
	
	copy_highpage(lower_page,page);
	flush_dcache_page(lower_page);
	SetPageUptodate(lower_page);
	set_page_dirty(lower_page);
	#endif
	if(wbc->for_reclaim){
		unlock_page(lower_page);
		goto out_release;
	}

	BUG_ON(!lower_mapping->a_ops->writepage);
	wait_on_page_writeback(lower_page);
	clear_page_dirty_for_io(lower_page);
	rc = lower_mapping->a_ops->writepage(lower_page,wbc);

	if(rc <0 )
		goto out_release;

	if(rc == AOP_WRITEPAGE_ACTIVATE){
		rc =0;
		unlock_page(lower_page);
	}
	
	fsstack_copy_attr_times(inode,lower_inode);
	
 out_release:
	page_cache_release(lower_page);
 out:
	unlock_page(page);
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG_EXIT(rc);
#endif
	return rc;
}

static int wrapfs_readpage(struct file *file,struct page *page)
{
	int err =0;
	
	struct file *lower_file;
	struct inode *inode;
	struct inode *lower_inode;
#ifndef WRAPFS_CRYPTO
	mm_segment_t old_fs;

	char *page_data = NULL;
	mode_t old_mode;
#endif
	#ifdef WRAPFS_CRYPTO
	
	struct wrapfs_crypt_stat *crypt_stat;
	BUG_ON(use_mmap!=1);
        crypt_stat = &WRAPFS_SB(file->f_dentry->d_sb)->crypt_stat;
	if(crypt_stat->flags & WRAPFS_KEY_NULL){
		printk(KERN_DEBUG "KEY is not set! Abort!\n");
		err = -ENOENT;
		goto out;
	}
	#endif
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG;
#endif
	lower_file = wrapfs_lower_file(file);

	
	BUG_ON(lower_file == NULL);

	inode = file->f_path.dentry->d_inode;
	lower_inode = wrapfs_lower_inode(inode);
	#ifdef WRAPFS_CRYPTO
	
	err = wrapfs_decrypt_page(page,lower_file);
	
	
	#else
	page_data = (char*) kmap(page);
	
        
	
	lower_file->f_pos = page_offset(page);

	
	old_fs = get_fs();
	set_fs (KERNEL_DS);

	old_mode = lower_file->f_mode;
	lower_file->f_mode |= FMODE_READ;
	err = vfs_read(lower_file,page_data,PAGE_CACHE_SIZE,
		       &lower_file->f_pos);
	lower_file->f_mode = old_mode;

	set_fs(old_fs);
	if(err >=0 && err < PAGE_CACHE_SIZE)
		memset(page_data + err, 0, PAGE_CACHE_SIZE - err);

	kunmap(page);
	#endif

	if(err <0)
		goto out;
	
	err =0;
	fsstack_copy_attr_times(inode,lower_inode);

	flush_dcache_page(page);

 out:
	if(err==0)
		SetPageUptodate(page);
	else
		ClearPageUptodate(page);
	unlock_page(page);
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG_EXIT(err);
#endif
	return err;
}

static int wrapfs_write_begin (struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	
	int err =0;
	
	
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	
	struct page *page;
	struct file *lower_file;
	
	loff_t prev_page_end_size;

#ifdef WRAPFS_CRYPTO	
	struct wrapfs_crypt_stat *crypt_stat;
	BUG_ON(use_mmap!=1);
#endif 
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG;
#endif
	lower_file = wrapfs_lower_file(file);
	
	page = grab_cache_page_write_begin(mapping,index,flags);
	
	if(!page) 
		return -ENOMEM;
	*pagep = page;
	
	#ifdef WRAPFS_CRYPTO
	crypt_stat = &WRAPFS_SB(mapping->host->i_sb)->crypt_stat;
	if(crypt_stat->flags & WRAPFS_KEY_NULL){
		printk(KERN_DEBUG "KEY is not set! Abort!\n");
		err = -ENOENT;
		goto out;
	}
	#endif
	prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
	if(!PageUptodate(page)){
		if(prev_page_end_size >= i_size_read(page->mapping->host)){
			
			zero_user(page,0,PAGE_CACHE_SIZE);
		}
		else{
			#ifdef WRAPFS_CRYPTO
			err = wrapfs_decrypt_page(page,lower_file);
			if(err){
				printk(KERN_ERR "%s: Error decrypting"
				       "page at index [%ld];"
				       "err = [%d]\n",
				       __func__,page->index,err);
				ClearPageUptodate(page);
				goto out;
			}
			#endif
		}
	      
		SetPageUptodate(page);
	}
/*
	if(index != 0){
		if(prev_page_end_size > i_size_read(page->mapping->host)){

			printk(KERN_DEBUG "We got holes!\n");
						
			err = wrapfs_truncate(file->f_path.dentry,
					     prev_page_end_size);
			if(err){
				printk(KERN_ERR "%s: Error on attempt to"
				       "truncate to higher offset,"
				       "return rc = [%d]\n ",__func__,
				       err);
				goto out;
			}
			
			
		}
	}
*/	
	
	/* zero out from start*/
	
	if((i_size_read(mapping->host) == prev_page_end_size) &&
	   (pos!=0))
		zero_user(page,0,PAGE_CACHE_SIZE);
	goto out;
	
out:
	if(unlikely(err)){
		unlock_page(page);
		page_cache_release(page);
		*pagep = NULL;
	}
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG_EXIT(err);
#endif
	return err;
}

static int wrapfs_write_end(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned copied,
			    struct page *page,void *fsdata)
{
	
	int err = -ENOMEM;
       
	unsigned from = pos &(PAGE_CACHE_SIZE -1);
	unsigned to = from+copied;
	
	int need_unlock_page =1;

	struct inode *upper_inode = page->mapping->host;
	struct inode *lower_inode;
	struct file *lower_file =NULL;
	

	
#ifdef WRAPFS_CRYPTO
	struct wrapfs_crypt_stat *crypt_stat = NULL;		
	char *tmp_page_data =NULL;
	struct page *tmp_page = NULL;
#endif 

	char *page_data = NULL;
	mm_segment_t old_fs;
	
	loff_t offset;
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG;
#endif
#ifdef WRAPFS_CRYPTO
	BUG_ON(use_mmap !=1);
	crypt_stat = &WRAPFS_SB(mapping->host->i_sb)->crypt_stat;
	if(crypt_stat->flags & WRAPFS_KEY_NULL){
		printk(KERN_DEBUG "KEY is not set! Abort!\n");
		err = -ENOENT;
		goto out;
	}

	tmp_page= alloc_page(GFP_USER);
	if(!tmp_page){
		err = -ENOMEM;
		printk(KERN_ERR "Error allocating memory for"
		       " tmp page\n");
		goto out;
	}
#endif
	BUG_ON(file ==NULL);
       
	lower_file = wrapfs_lower_file(file);
	lower_inode = wrapfs_lower_inode(upper_inode);

       	
       
	err = fill_zero_to_eofpage(page,to);
	if(err){
		printk(KERN_WARNING "Error fill zeros at eof page\n");
		goto out;
	}
	if(pos+copied > i_size_read(upper_inode)){
	      
		i_size_write(upper_inode,pos + copied);
		balance_dirty_pages_ratelimited(mapping);
	}
	
	page_data = (char*)kmap(page);
	
#ifdef WRAPFS_CRYPTO
	tmp_page_data = (char*)kmap(tmp_page);
	memset(tmp_page_data,0,PAGE_CACHE_SIZE);
	kunmap(tmp_page);

        err = wrapfs_encrypt_page(page,tmp_page);
	if(err){
		printk(KERN_DEBUG "%s: Encryption page and"
		       " copy to lower failed,return %d",
		       __func__,err);
		ClearPageUptodate(page);
		goto out;
	}
	tmp_page_data = (char*)kmap(tmp_page);	
#endif

      	offset = page_offset(page) +from;
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	/*
	printk(KERN_DEBUG "offset is %lld,to = %u "
	       "copied = %d\n", offset,to,copied);
	*/
#ifdef WRAPFS_CRYPTO
	err = vfs_write(lower_file,tmp_page_data,copied,&offset);
#else
	err = vfs_write(lower_file,page_data+from,copied,&offset);
#endif        
	set_fs(old_fs);
	
	kunmap(page);
	
	
	if(err<0){
		printk(KERN_ERR "%s: Error writing lower_file,return %d\n",__func__,err);
		goto out;
	}
	
      
	
	/*fsstack_copy_inode_size(upper_inode,lower_inode);
	 */
        fsstack_copy_attr_times(upper_inode,lower_inode);
		
	mark_inode_dirty_sync(upper_inode);
	unlock_page(page);
	need_unlock_page =0;
	err = copied;
out:
	if(err<0)
		ClearPageUptodate(page);
	#ifdef WRAPFS_CRYPTO
	if(tmp_page){
		kunmap(tmp_page);
		__free_page(tmp_page);
	}
	#endif
	if(need_unlock_page)
		unlock_page(page);
	
	
	page_cache_release(page);
#ifdef EXTRA_CREDIT
	if(dbg_bitmap & DBG_ADDR_OP)
		UDBG_EXIT(err);
#endif
	return err;
	
	/*
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned from = pos & (PAGE_CACHE_SIZE -1);
	unsigned to   = from + copied;
	struct inode *upper_inode = mapping ->host;
       
      

	int rc =0;
	int need_unlock_page =1;
	
	rc = fill_zeros_to_end_of_page(page,to);
	if(rc){
		printk(KERN_WARNING "Error filling zeros\n");
		goto out;
	}
        printk(KERN_DEBUG "Entering write_end\n");
	

	set_page_dirty(page);
	unlock_page(page);
	need_unlock_page =0;
	if(pos+copied > i_size_read(upper_inode)){
		i_size_write(upper_inode,pos+copied);
		
		balance_dirty_pages_ratelimited(mapping);
		
	}
	rc = copied;
 out:
	if(need_unlock_page)
		unlock_page(page);
	
	return rc;
	*/
}

static sector_t wrapfs_bmap(struct address_space *mapping, sector_t block)
{
	int rc =0;
	struct inode *inode;
	struct inode *lower_inode;
	
	inode = (struct inode*)mapping->host;
	lower_inode = wrapfs_lower_inode(inode);

	if(lower_inode->i_mapping->a_ops->bmap)
		rc = lower_inode->i_mapping->a_ops->bmap(lower_inode->i_mapping,
							 block);

	return rc;
}
/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
const struct address_space_operations wrapfs_aops = {
	
     	.writepage = wrapfs_writepage,
        .readpage  = wrapfs_readpage,
	.write_begin = wrapfs_write_begin,
	.write_end  = wrapfs_write_end,
	.bmap = wrapfs_bmap
};

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault		= wrapfs_fault,
};
