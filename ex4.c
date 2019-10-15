#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static char *int_str;
static char procStr[100] = {0};

/* [X1: point 1]
 * These are macros to let the users know more about the following linux kernel 
 * module license, author and discription
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Kulneet Singh]");
MODULE_DESCRIPTION("LKP Exercise 4");

/* [X2: point 1]
 * Macro to that specifies the parameters passed to the the kernel module,
 * name of the the variable, the type and the permissions for the file
 */
module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);

/* [X3: point 1]
 * Macro to decribe the parameters passed to the module
 */
MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

/* [X4: point 1]
 * Declaring the data structures to be used in this module
 */
#define MY_HASH_BITS 10
static int elementCount = 0;
static LIST_HEAD(mylist);
static DEFINE_HASHTABLE(myHash, MY_HASH_BITS);
// Declaring a rbtree root node
static struct rb_root myTree = RB_ROOT;
// Declaring a Radix Tree Root
RADIX_TREE(rad_tree, GFP_ATOMIC | __GFP_ACCOUNT);

static int ex4_proc_show(struct seq_file *m, void *v) {
  seq_printf(m, "%s", procStr);
  return 0;
}

static int ex4_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, ex4_proc_show, NULL);
}

static const struct file_operations ex4_proc_fops = {
  .owner = THIS_MODULE,
  .open = ex4_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};

/* [X5: point 1]
 * Declaring the entry struct for the the entries in the data structures, which
 * include the the data value and the list head data structure that contains the next and 
 * previous pointers
 */
struct entry {
	int val;
	struct list_head list;
};

// Declaring a structure for each entry in the hash table
struct hashEntry {
	int val;
	struct hlist_node hash_node;
};

// Declaring the structure of a rb_node
struct rb_type {
	struct rb_node node;
	int val;
};

// Function to insert a new node into the red black tree
static void insertRB(struct rb_root *root, struct rb_type *data) {
	struct rb_node **link = &(root->rb_node);
	struct rb_node *parent = NULL;
	struct rb_type *entry;

	/* Traverse the rbtree to find the right place to insert */
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct rb_type, node);
		if (data->val < entry->val) {
			link = &parent->rb_left;
		} 
		else {
			link = &parent->rb_right;
		}
	}
	/* Insert a new node */
	rb_link_node(&data->node, parent, link);
	/* Re-balance the rbtree if necessary */
	rb_insert_color(&data->node, root);
}

// Function to remove elements from a rbtree
static void removeRB(struct rb_root *root, struct rb_type *data) {
	rb_erase(&data->node, root);
}

static int store_value(int val)
{
	/* [X6: point 10]
	 * Allocate a struct entry of which val is val
	 * and add it to the tail of mylist.
	 * Return 0 if everything is successful.
	 * Otherwise (e.g., memory allocation failure),
	 * return corresponding error code in error.h (e.g., -ENOMEM).
	 */

	// Declaring a pointer to an entry 
	struct entry * entryPtr;

	// Declare a dynamically allocated hashEntry struct
	struct hashEntry *hashEntryPtr;

	// Declaring a dynamically allocated element for a rbtree
	struct rb_type *new_rbPtr;

	// Increment total element count
	elementCount++;

	// Allocating data for a new entry
	entryPtr = (struct entry *)kmalloc(sizeof(struct entry), GFP_KERNEL); 
	// Error checking the allocation of memory by kmalloc, and returning error if unsuccessful
	if(!entryPtr) {
		return -ENOMEM;
	}
	// Setting the value of the dynamically allocated entry
	entryPtr->val = val;
	// Adding the new element to the list 
	list_add(&entryPtr->list, &mylist);

	// START: Code to insert an element in to the hash table
	//Allocating data for new entry
	hashEntryPtr = (struct hashEntry *)kmalloc(sizeof(struct hashEntry), GFP_KERNEL);
	// Check for errors in allocation
	if(!hashEntryPtr) {
		return -ENOMEM;
	}
	// Set the value of the entry
	hashEntryPtr->val = val;
	// Add the value to the Hash Table
	hash_add(myHash, &hashEntryPtr->hash_node, val);

	// START: Code to add values to rb_tree
	new_rbPtr = (struct rb_type *)kmalloc(sizeof(struct rb_type), GFP_KERNEL);
	new_rbPtr->val = val;
	insertRB(&myTree, new_rbPtr);
	
	// Returning 0 indicating there was no error in allocation
	return 0;
}

static void test_linked_list(void)
{
	/* [X7: point 10]
	 * Print out value of all entries in all the data structures.
	 */

	// counter variable used for iterating
	int i;

	// Pointer to actual data in list
	struct entry * curEntry;

	// Declaring Hash variables to store temp values
	int bkt;
	struct hashEntry * curHash;

	// Declaring a node struct to iterate through a rbtree
	struct rb_node *node1;

	//Printing label for linked list
	printk(KERN_CONT "Linked list: ");
	sprintf(procStr + strlen(procStr), "Linked list: ");
	// For loop to iterate through the list and print out the values 
	i = 0;
	list_for_each_entry(curEntry, &mylist, list) {
		if (i < elementCount-1) {
			printk(KERN_CONT "%d, ", curEntry->val);
			sprintf(procStr + strlen(procStr), "%d, ", curEntry->val);
		} 
		else {
			printk(KERN_CONT "%d\n", curEntry->val);
			sprintf(procStr + strlen(procStr), "%d\n", curEntry->val);
		}
		i++;
	}

	// START: Code to print all the element contained in the Hash Table
	printk(KERN_CONT "Hash table: ");
	sprintf(procStr + strlen(procStr), "Hash table: ");

	i = 0;
	hash_for_each(myHash, bkt, curHash, hash_node) {
		if (i < elementCount-1) {
			printk(KERN_CONT "%d, ", curHash->val);
			sprintf(procStr + strlen(procStr), "%d, ", curHash->val);
		} 
		else {
			printk(KERN_CONT "%d\n", curHash->val);
			sprintf(procStr + strlen(procStr), "%d\n", curHash->val);
		}
		i++;	
	}

	// START: Code to iterate through the rbtree and print its contents
	printk(KERN_CONT "Red-Black tree: ");
	sprintf(procStr + strlen(procStr), "Red-Black tree: ");
	for (node1 = rb_first(&myTree); node1; node1 = rb_next(node1)) {
		if (rb_next(node1)){
			printk(KERN_CONT "%d, ", rb_entry(node1, struct rb_type, node)->val);
			sprintf(procStr + strlen(procStr), "%d, ", rb_entry(node1, struct rb_type, node)->val);
		}
		else {
			printk(KERN_CONT "%d\n", rb_entry(node1, struct rb_type, node)->val);
			sprintf(procStr + strlen(procStr), "%d\n", rb_entry(node1, struct rb_type, node)->val);
		}
	}
}


static void destroy_linked_list_and_free(void)
{
	/* [X8: point 10]
	 * Free all entries in mylist.
	 */

	// Pointers for the current entry in the list and the next entry
	struct entry *curEntry, *nextEntry;

	// Declaring all neccesary temporary variables fo hash lists
	struct hashEntry *curHash;
	struct hlist_node *temp_hlist;
	int bkt;

	// Declaring a node struct to iterate through a rbtree
	struct rb_type *cur_rbNode;
	struct rb_type *next_rbNode;

	// For loop to iterate through the list and remove each entry
	// and correspondingly free the allocated memory
	list_for_each_entry_safe(curEntry, nextEntry, &mylist, list) {
		list_del(&curEntry->list);
		kfree(curEntry);
	}

	// START: Code to free all entries from hash table
	// For loop to safely iterate through the entryies while removing
	hash_for_each_safe(myHash, bkt, temp_hlist, curHash, hash_node) {
		hash_del(&curHash->hash_node);
		kfree(curHash);
	}

	// START: Code to free all entries from hash table
	// For loop to safely iterate through the entryies while removing
	rbtree_postorder_for_each_entry_safe(cur_rbNode, next_rbNode, &myTree, node) {
		removeRB(&myTree, cur_rbNode);
		kfree(cur_rbNode);
	}
}


static int parse_params(void)
{
	int val, err = 0;
	char *p, *orig, *params;


	/* [X9: point 1]
	 * The perameter string is duplicated and stored in a char array
	 */
	params = kstrdup(int_str, GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	orig = params;

	/* [X10: point 1]
	 * This while loop parses through the input string and tokenizes based on the 
	 * comma as a delimeter
	 */
	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;
		/* [X11: point 1]
		 * Each parsed number is being converted in to an integer
		 */
		err = kstrtoint(p, 0, &val);
		if (err)
			break;

		/* [X12: point 1]
		 * Once the value of the string number is converted to an int,
		 * it is then passed to the store value function to add it
		 * to the linked list
		 */
		err = store_value(val);
		if (err)
			break;
	}

	/* [X13: point 1]
	 * the original value for the parameters is now freed
	 */
	kfree(orig);
	return err;
}

static void run_tests(void)
{
	/* [X14: point 1]
	 * The testing function is called.
	 */
	test_linked_list();
}

static void cleanup(void)
{
	/* [X15: point 1]
	 * A kernel info message is printed and the clean up function is called 
	 */
	printk(KERN_INFO "\nCleaning up...\n");

	destroy_linked_list_and_free();
}

static int __init ex4_init(void)
{
	int err = 0;

	/* [X16: point 1]
	 * This code prints an error if the function is not passed the right 
	 * arguments
	 */
	if (!int_str) {
		printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
		return -1;
	}

	/* [X17: point 1]
	 * This code calls the parse params function, then if an error is found 
	 * the function returns gracefully
	 */
	err = parse_params();
	if (err)
		goto out;

	/* [X18: point 1]
	 * The test function is being called 
	 */
	proc_create("proj2", 0, NULL, &ex4_proc_fops);
	run_tests();
out:
	/* [X19: point 1]
	 * The clean function is called and the error is returned
	 */
	cleanup();
	return err;
}

static void __exit ex4_exit(void)
{
	/* [X20: point 1]
	 * This is a return, for the module to end
	 */
	remove_proc_entry("proj2", NULL);

	return;
}

/* [X21: point 1]
 * The macro to specify the init call for the module 
 */
module_init(ex4_init);

/* [X22: point 1]
 * The macro to specify the exit call for the module
 */
module_exit(ex4_exit);
