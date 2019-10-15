#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>

// Global Count Variable
static int count = 0;

#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "hello_world_show";

static struct kprobe kp = {
	.symbol_name	= symbol,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    pr_info("Inside kprobe prehandler.\n");
    count = count + 1;
    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)				
{
    pr_info("Inside kprobe posthandler.\n");
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

static int hello_world_show(struct seq_file *m, void *v) {
  seq_printf(m, "Hello World\nCount = %d\n", count);
  return 0;
}

static int hello_world_open(struct inode *inode, struct  file *file) {
  return single_open(file, hello_world_show, NULL);
}

static const struct file_operations hello_world_fops = {
  .owner = THIS_MODULE,
  .open = hello_world_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

static int __init hello_world_init(void) {
    int ret;
    proc_create("perftop", 0, NULL, &hello_world_fops);
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %p\n", kp.addr);

    return 0;
}

static void __exit hello_world_exit(void) {
    unregister_kprobe(&kp);
    remove_proc_entry("perftop", NULL);
    pr_info("kprobe at %p unregistered\n", kp.addr);
}

MODULE_LICENSE("GPL");
module_init(hello_world_init);
module_exit(hello_world_exit);