#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/jhash.h>

// Declaring global spinlock 
DEFINE_SPINLOCK(my_lock);

// Adding code to define stack_trace_save_user function
typedef typeof(&stack_trace_save_user) stack_trace_save_user_fn;
#define stack_trace_save_user (* (stack_trace_save_user_fn)kallsyms_stack_trace_save_user)
void *kallsyms_stack_trace_save_user = NULL;
#define STACK_DEPTH 24
#define HASH_INIT 10

// Hashtable Declarations
#define MY_HASH_BITS 10
static DEFINE_HASHTABLE(myHash, MY_HASH_BITS);

// Declaring a structure for each entry in the hash table
struct hashEntry {
  u32 key;
  int val;
  unsigned int PID;
  unsigned long stack_trace[STACK_DEPTH];
  unsigned int numEntries;
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
  unsigned int pid = t->pid;
  struct hashEntry *hashEntryPtr;
  bool found = false;
  // Declaring Hash variables to store temp values
	int bkt;
	struct hashEntry * curHash;
  bool kernelTask = false;
  int i;
  // Variables to handle new stack traces
  unsigned long store[STACK_DEPTH];
  u32 keyVal;

  if(t->mm == NULL)
  {
    kernelTask = true;
    hashEntryPtr->numEntries = stack_trace_save(hashEntryPtr->stack_trace, STACK_DEPTH-1, 0);
  }
  else 
  {
    hashEntryPtr->numEntries = stack_trace_save_user(hashEntryPtr->stack_trace, STACK_DEPTH-1);
  }

  for(i = 0; i < STACK_DEPTH; i++)
  {
    store[i] = hashEntryPtr->stack_trace[i];
  }

  store[STACK_DEPTH-1] = (unsigned long)pid;

  keyVal = jhash(store, STACK_DEPTH, HASH_INIT);

  spin_lock(&my_lock);

  hash_for_each_rcu(myHash, bkt, curHash, hash_node) {
    if(curHash->key == keyVal)
    {
      curHash->val++;
      found = true;
      // pr_info("Updated pid is %d and count is %d.\n", curHash->PID, curHash->val);
    }
  }

  if(!found)
  {
    hashEntryPtr = (struct hashEntry *)kmalloc(sizeof(struct hashEntry), GFP_ATOMIC);
    // Check for errors in allocation
    if(!hashEntryPtr) {
      return -ENOMEM;
    }
    // Set the value of the entry
    hashEntryPtr->val = 1;
    hashEntryPtr->PID = pid;
    hashEntryPtr->key = keyVal;
    // Add the value to the Hash Table
    hash_add_rcu(myHash, &hashEntryPtr->hash_node, keyVal);
    // pr_info("The new pid is %d and count is %d.\n", hashEntryPtr->PID, hashEntryPtr->val);
  }
  
  spin_unlock(&my_lock);
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
  spin_lock(&my_lock);
	hash_for_each_safe(myHash, bkt, temp_hlist, curHash, hash_node) {
		hash_del_rcu(&curHash->hash_node);
		kfree(curHash);
	}
  spin_unlock(&my_lock);
}

static int hello_world_show(struct seq_file *m, void *v) {
  // Declaring Hash variables to store temp values
	int bkt;
	struct hashEntry * curHash;
  char printBuf[MAX_SYMBOL_LEN] = {0};
  spin_lock(&my_lock);
  hash_for_each_rcu(myHash, bkt, curHash, hash_node) {
    stack_trace_snprint(printBuf, MAX_SYMBOL_LEN, curHash->stack_trace, curHash->numEntries, 4);
    seq_printf(m, "PID: %d Count: %d\n%s\n", curHash->PID, curHash->val, printBuf);
	}
  spin_unlock(&my_lock);
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
  kp.pre_handler = handler_pre;
  kp.post_handler = handler_post;
  kp.fault_handler = handler_fault;
  ret = register_kprobe(&kp);

  //Symbol lookup
  kallsyms_stack_trace_save_user = (void*)kallsyms_lookup_name("stack_trace_save_user");

  if (ret < 0) {
    pr_err("register_kprobe failed, returned %d\n", ret);
    return ret;
  }
  pr_info("Planted kprobe at %p\n", kp.addr);

  proc_create("perftop", 0, NULL, &hello_world_fops);
  return 0;
}

static void __exit hello_world_exit(void) {
  unregister_kprobe(&kp);
  cleanup();
  remove_proc_entry("perftop", NULL);
  pr_info("kprobe at %p unregistered\n", kp.addr);
}

MODULE_LICENSE("GPL");
module_init(hello_world_init);
module_exit(hello_world_exit);