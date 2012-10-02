#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/module.h>

asmlinkage long (*STUB_wrapper_syscall) (void __user *args)= NULL;

EXPORT_SYMBOL(STUB_wrapper_syscall);

asmlinkage long sys_xcrypt(void __user *args)
{
	if(STUB_wrapper_syscall){
		return STUB_wrapper_syscall(args);
	}
	else {
		return -ENOSYS;
	}
}
