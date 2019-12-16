//INCLUDES/////////////////////////////////////////////////////////////////////

#include <linux/module.h>
#include <linux/lsm_hooks.h>


//DEFINES//////////////////////////////////////////////////////////////////////

#define MODULE_NAME "afprotect"


//ABOUT////////////////////////////////////////////////////////////////////////

MODULE_AUTHOR("afakeman");
MODULE_DESCRIPTION("Simple Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.2");


//HOOKS/////////////////////////////////////////////////////////////////////////

int af_path_chown(const struct path * a, kuid_t b,  kgid_t c) {
    if (b.val == 2000) {
        return -EACCES;
    }
    return 0;
}

static struct security_hook_list stub_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(path_chown, af_path_chown),
};

//INIT/////////////////////////////////////////////////////////////////////////

static __init int ptlsm_init(void)
{
        security_add_hooks(stub_hooks, ARRAY_SIZE(stub_hooks), "afprotect");

		printk(KERN_ALERT "AFProtect started");

		return 0;
}

security_initcall(ptlsm_init);
