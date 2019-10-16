#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/slab.h>


// Global Count Variable
static int count = 0;

// Hashtable Declarations
#define MY_HASH_BITS 10
static DEFINE_HASHTABLE(myHash, MY_HASH_BITS);

// Declaring a structure for each entry in the hash table
struct hashEntry {
	int val;
	struct hlist_node hash_node;
};

// Kprobe Declarations
#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "pick_next_task_fair";

static struct kprobe kp = {
	.symbol_name	= symbol,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
  struct task_struct *t = (struct task_struct *) regs->si;
  int pid = t->pid;
  struct hashEntry *hashEntryPtr;
  bool found = false;
  int i = 0;
  // Declaring Hash variables to store temp values
	int bkt;
	struct hashEntry * curHash;

  if(!hash_empty(myHash))
  {
    hash_for_each(myHash, bkt, curHash, hash_node) {
      pr_info("The pid is %d and the count is %d\n", bkt, curHash->val);
    }
  }
  else
  {
    hashEntryPtr = (struct hashEntry *)kmalloc(sizeof(struct hashEntry), GFP_KERNEL);
    // Check for errors in allocation
    if(!hashEntryPtr) {
      return -ENOMEM;
    }
    // Set the value of the entry
    hashEntryPtr->val = 1;
    // Add the value to the Hash Table
    hash_add(myHash, &hashEntryPtr->hash_node, pid);
  }
  
  pr_info("The pid of the scheduling task is %d.\n", pid);

  return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)				
{
  // pr_info("Inside kprobe posthandler.\n");
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

static void cleanup(void)
{
	// Declaring all neccesary temporary variables fo hash lists
	struct hashEntry *curHash;
	struct hlist_node *temp_hlist;
	int bkt;

	// START: Code to free all entries from hash table
	// For loop to safely iterate through the entryies while removing
	hash_for_each_safe(myHash, bkt, temp_hlist, curHash, hash_node) {
		hash_del(&curHash->hash_node);
		kfree(curHash);
	}
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
    cleanup();
    unregister_kprobe(&kp);
    remove_proc_entry("perftop", NULL);
    pr_info("kprobe at %p unregistered\n", kp.addr);
}

MODULE_LICENSE("GPL");
module_init(hello_world_init);
module_exit(hello_world_exit);