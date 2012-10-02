#include <linux/fs.h>
#include <linux/pagemap.h>
#include "wrapfs.h"

int wrapfs_read_lower(struct file *lower_file,char *data, loff_t offset, size_t size)
{
	      
	mm_segment_t fs_save;
	ssize_t rc;

	
	if(!lower_file)
		return -EIO;
	fs_save = get_fs();
	set_fs(get_ds());
	rc = vfs_read(lower_file,data,size,&offset);
	printk(KERN_DEBUG "REACH HERE?? rc is %d\n",rc);
	set_fs(fs_save);

	
	return rc;
}
int wrapfs_read_lower_page_segment(struct file* lower_file,struct page *page_upper,
				   pgoff_t page_index,
				   size_t offset_in_page,size_t size)
{
	char *virt;
	loff_t offset;
	int rc;
	
	offset = (((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page;

	virt = (char*)kmap(page_upper);

	rc = wrapfs_read_lower(lower_file,virt,offset,size);
	if(rc>0){
		printk(KERN_DEBUG "wrapfs_read_lower success!\n");
		rc =0;
	}
	kunmap(page_upper);
	flush_dcache_page(page_upper);
	return rc;
}
