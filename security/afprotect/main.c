#include <linux/lsm_hooks.h>

int af_path_chown(const struct path * a, kuid_t b,  kgid_t c) {
    if (b.val == 2000) {
        return -EACCES;
    }
    return 0;
}

static struct security_hook_list stub_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(path_chown, af_path_chown),
};

static __init int afprotect_init(void)
{
        security_add_hooks(stub_hooks, ARRAY_SIZE(stub_hooks), "afprotect");
		printk(KERN_ALERT "AFProtect started");
		return 0;
}

security_initcall(afprotect_init);
