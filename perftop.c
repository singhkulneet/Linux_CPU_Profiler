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
#include <asm/msr.h>
#include <linux/rbtree.h>
#include <linux/kallsyms.h>

// Global time to keep track of time
static long long prevTime = 0;

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

// Declaring a rbtree root node
static struct rb_root myTree = RB_ROOT;

// Declaring a structure for each entry in the hash table
struct hashEntry {
  unsigned int key;
  int val;
  unsigned int PID;
  unsigned long stack_trace[STACK_DEPTH];
  char comm[16];
  unsigned int numEntries;
  bool kernel;
  unsigned long long runTime;
  struct hlist_node hash_node;
};

struct rb_type {
  unsigned int key;
  int val;
  unsigned int PID;
  unsigned long stack_trace[STACK_DEPTH];
  char comm[16];
  unsigned int numEntries;
  bool kernel;
  unsigned long long runTime;
	struct rb_node node;
};

// Function to insert a new node into the red black tree
static int insertRB(struct rb_root *root, struct rb_type *data) 
{
	struct rb_node **link = &(root->rb_node);
	struct rb_node *parent = NULL;
	struct rb_type *entry;

	/* Traverse the rbtree to find the right place to insert */
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct rb_type, node);
		if (data->runTime < entry->runTime) {
			link = &parent->rb_left;
		} 
		else { // if(data->runTime < entry->runTime) {
			link = &parent->rb_right;
		}
    // else {
    //   pr_info("ERROR: tried to add duplicate entry to rbtree");
    //   return -1;
    // }
	}
	/* Insert a new node */
	rb_link_node(&data->node, parent, link);
	/* Re-balance the rbtree if necessary */
	rb_insert_color(&data->node, root);

  return 0;
}

struct rb_type *my_search(struct rb_root *root, unsigned long long time)
{
  struct rb_node *node = root->rb_node;

  while (node) {
    struct rb_type *data = container_of(node, struct rb_type, node);

    if (time < data->runTime)
      node = node->rb_left;
    else if (time < data->runTime)
      node = node->rb_right;
    else
      return data;
  }
  return NULL;
}

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
  struct rb_type *rbEntryPtr;
  bool found = false;
  // Declaring Hash variables to store temp values
	int bkt;
	struct hashEntry * curHash;
  bool kernelTask = false;
  int i;
  // Variables to handle new stack traces
  unsigned long store[STACK_DEPTH];
  unsigned int entries;
  unsigned int keyVal;
  unsigned long long curTime = rdtsc();
  unsigned long long difTime = 0;

  if(prevTime != 0)
  {
    difTime = curTime - prevTime;
  }
  else 
  {
    prevTime = curTime;
  }

  spin_lock(&my_lock);
  if(t->mm == NULL)
  {
    kernelTask = true;
    entries = stack_trace_save(store, STACK_DEPTH-1, 0);
  }
  else 
  {
    entries = stack_trace_save_user(store, STACK_DEPTH-1);
  }

  store[STACK_DEPTH-1] = (unsigned long)pid;

  keyVal = jhash(store, STACK_DEPTH, HASH_INIT);

  hash_for_each(myHash, bkt, curHash, hash_node) {
    if(curHash->key == keyVal)
    {
      curHash->val++;
      
      // Handling existing tasks in rbtree and updating
      rbEntryPtr = my_search(&myTree, curHash->runTime);
      if (rbEntryPtr) {
        rb_erase(&rbEntryPtr->node, &myTree);
        rbEntryPtr->runTime = rbEntryPtr->runTime + difTime;
        rbEntryPtr->val++;
        insertRB(&myTree, rbEntryPtr);
      }

      curHash->runTime = curHash->runTime + difTime;
      found = true;
    }
  }

  if(!found)
  {
    hashEntryPtr = (struct hashEntry *)kmalloc(sizeof(struct hashEntry), GFP_ATOMIC);
    rbEntryPtr = (struct rb_type *)kmalloc(sizeof(struct rb_type), GFP_ATOMIC);

    // Check for errors in allocation
    if(!hashEntryPtr) {
      return -ENOMEM;
    }
    // Set the value of the entry
    hashEntryPtr->val = 1;
    hashEntryPtr->PID = pid;
    hashEntryPtr->key = keyVal;
    hashEntryPtr->numEntries = entries;
    hashEntryPtr->kernel = kernelTask;
    hashEntryPtr->runTime = difTime;
    // Set the values for rbtree
    rbEntryPtr->val = 1;
    rbEntryPtr->PID = pid;
    rbEntryPtr->key = keyVal;
    rbEntryPtr->numEntries = entries;
    rbEntryPtr->kernel = kernelTask;
    rbEntryPtr->runTime = difTime;

    for(i = 0; i < STACK_DEPTH-1; i++)
    {
      hashEntryPtr->stack_trace[i] = store[i];
      rbEntryPtr->stack_trace[i] = store[i];
    }

    for(i = 0; i < 16; i++)
    {
      hashEntryPtr->comm[i] = t->comm[i];
      rbEntryPtr->comm[i] = t->comm[i];
    }

    // Add the value to the Hash Table
    hash_add(myHash, &hashEntryPtr->hash_node, keyVal);
    // Add entry to rbtree
    insertRB(&myTree, rbEntryPtr);
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
	// pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

static void cleanup(void)
{
	// Declaring all neccesary temporary variables fo hash lists
	struct hashEntry *curHash;
	struct hlist_node *temp_hlist;
	int bkt;

  // Declaring variables for removing rbtree entries
  struct rb_type *cur_rbNode;
	struct rb_type *next_rbNode;

	// START: Code to free all entries from hash table
	// For loop to safely iterate through the entryies while removing
  spin_lock(&my_lock);
	hash_for_each_safe(myHash, bkt, temp_hlist, curHash, hash_node) {
		hash_del(&curHash->hash_node);
		kfree(curHash);
	}

  // For loop to safely iterate through the entries of rbtree while removing (in reverse order)
	rbtree_postorder_for_each_entry_safe(cur_rbNode, next_rbNode, &myTree, node) {
		rb_erase(&cur_rbNode->node, &myTree);
		kfree(cur_rbNode);
	}
  spin_unlock(&my_lock);
}

static int hello_world_show(struct seq_file *m, void *v) {
  // Declaring Hash variables to store temp values
	// int bkt;
	// struct hashEntry * curHash;
  struct rb_type *cur_rbNode;
  struct rb_node *node;
	// struct rb_type *next_rbNode;
  char printBuf[250];
  int i = 1;
  int y = 0;
  int valid;

  spin_lock(&my_lock);
  // hash_for_each(myHash, bkt, curHash, hash_node) {
  //   stack_trace_snprint(printBuf, MAX_SYMBOL_LEN, curHash->stack_trace, curHash->numEntries, 2);
  //   seq_printf(m, "PID: %d\nCount: %d\nCommand: %s\nAccumulative time: %llu\nKernel Task: %s\nStack_Trace\\/\n%s\n", 
  //       curHash->PID, curHash->val, curHash->comm, curHash->runTime, curHash->kernel ? "True" : "False", printBuf);
	// }

  // rbtree_postorder_for_each_entry_safe(cur_rbNode, next_rbNode, &myTree, node) {
  for (node = rb_first(&myTree); node; node = rb_next(node)) {
    cur_rbNode = rb_entry(node, struct rb_type, node);
		if(i >= 21)
    {
      goto end;
    }

    if(cur_rbNode->kernel) {
      stack_trace_snprint(printBuf, MAX_SYMBOL_LEN, cur_rbNode->stack_trace, cur_rbNode->numEntries, 0);
      seq_printf(m, "Task: %d\nPID: %d\nCount: %d\nCommand: %s\nAccumulative time: %llu\nKernel Task: %s\nStack_Trace\\/\n%s\n", 
          i, cur_rbNode->PID, cur_rbNode->val, cur_rbNode->comm, cur_rbNode->runTime, cur_rbNode->kernel ? "True" : "False", printBuf);
    }
    else {
      seq_printf(m, "Task: %d\nPID: %d\nCount: %d\nCommand: %s\nAccumulative time: %llu\nKernel Task: %s\nStack_Trace\\/\n", 
          i, cur_rbNode->PID, cur_rbNode->val, cur_rbNode->comm, cur_rbNode->runTime, cur_rbNode->kernel ? "True" : "False");

      for(y = 0; y < cur_rbNode->numEntries; y++)
      {
        valid = sprint_symbol(printBuf, cur_rbNode->stack_trace[y]);
        if(valid) {
          seq_printf(m, "%s\n", printBuf);
        }
      }
    }

    seq_printf(m, "\n");

    i++;
	}

  // Jump label
  end:

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
  // pr_info("Planted kprobe at %p\n", kp.addr);

  proc_create("perftop", 0, NULL, &hello_world_fops);
  return 0;
}

static void __exit hello_world_exit(void) {
  unregister_kprobe(&kp);
  remove_proc_entry("perftop", NULL);
  cleanup();
  // pr_info("kprobe at %p unregistered\n", kp.addr);
}

MODULE_LICENSE("GPL");
module_init(hello_world_init);
module_exit(hello_world_exit);