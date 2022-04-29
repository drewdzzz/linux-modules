#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pgtable.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/radix-tree.h>

MODULE_LICENSE("GPL");

struct fifo_node {
    struct list_head list;
    int order;
    char *msg;
    unsigned long len;
};

struct fifo {
    struct list_head headlist;
} fifo;

atomic_t order;
spinlock_t lock;
struct radix_tree_root pid_order;

static void
fifo_insert(struct fifo_node *new_node)
{
    struct list_head *pos;
    struct fifo_node *item;
    spin_lock(&lock);
    list_for_each(pos, &(fifo.headlist)) {
        item = list_entry(pos, struct fifo_node, list);
        if (item->order > new_node->order) {
            break;
        }
    }
    list_add_tail(&new_node->list, pos);
    spin_unlock(&lock);
}

static struct fifo_node *
fifo_pop(void)
{
    void* res = NULL;
    struct fifo_node *item = NULL;

    spin_lock(&lock);
    item = list_entry(fifo.headlist.next, struct fifo_node, list);
    if(!list_empty(&(fifo.headlist))) {
        res = item;
        list_del(&(item->list));
    }
    spin_unlock(&lock);
    return res;
}

ssize_t 
my_write(struct file *file, const char __user * buf, size_t count, loff_t * ppos)
{
    struct fifo_node *node = NULL;
    int rc = 0; 
    int *cur_order = radix_tree_lookup(&pid_order, current->pid);
    if (cur_order == NULL) {
        pr_err("task 5 - write: this process haven't opened the file. It's a bug!");
        return -1;    
    }
    node = vmalloc(sizeof(*node));
    if (node == NULL) {
        pr_err("task 5 - write: cannot allocate space for fifo node");
        return -1;
    }
    node->len = count;
    node->order = *cur_order;
    node->msg = vmalloc(count);
    if (node->msg == NULL) {
        pr_err("task 5 - write: cannot allocate space for msg");
        vfree(node);
        return -2;
    }
    rc = copy_from_user(node->msg, buf, count);
    if (rc != 0) {
        pr_err("task 5 - write: cannot copy msg from user");
        vfree(node->msg);
        vfree(node);
    }
    fifo_insert(node);
    return count;
}

ssize_t	
my_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    int rc = 0;
    size_t len = 0;
    struct fifo_node *node = fifo_pop();

    if (node == NULL) {
        pr_warn("task 5 - read: list is empty");
        return 0;
    }
    len = node->len;
    if (count < len) {
        pr_warn("task 5 - read: msg len is more than read buffer");
        len = count;
    }
    rc = copy_to_user(buf, node->msg, len);
    vfree(node->msg);
    vfree(node);
    if (rc != 0) {
        pr_warn("task 5 - read: cannot copy to user");
        return rc;
    }
    return len;
}

int 
my_open(struct inode *inode, struct  file *file)
{
    int *cur_order = vmalloc(sizeof(int));
    int rc = 0;

    if (cur_order == NULL) {
        pr_err("task 5 - open file: cannot alloc data for pid tree");
        return -1;
    }
    *cur_order = atomic_fetch_add(1, &order);
    rc = radix_tree_insert(&pid_order, current->pid, cur_order);
    if (rc != 0) {
        pr_err("task 5 - open file: cannot insert to pid tree");
        vfree(cur_order);
        return rc;
    }
    rc = single_open(file, NULL, NULL);
    if (rc != 0) {
        pr_err("task 5 - open file: cannot open file");
        radix_tree_delete(&pid_order, current->pid);
        vfree(cur_order);
        return rc;
    }
    return 0;
}

int 
my_release(struct inode *inode, struct  file *file)
{
    void *data = radix_tree_delete(&pid_order, current->pid);
    if (data != NULL)
        vfree(data);
    return single_release(inode, file);
}

static struct proc_dir_entry *proc_entry;

static const struct proc_ops proc_fops = {
 .proc_write = my_write,
 .proc_read = my_read,
 .proc_open = my_open,
 .proc_release = my_release,
};

static int __init
task5_init(void) {
    atomic_set(&order, 0);
    spin_lock_init(&lock);
    INIT_RADIX_TREE(&pid_order, 0);
    pr_info("hello from task 5: %s\n", __func__);
    proc_entry = proc_create("fifa20", 0, NULL, &proc_fops);
    if (proc_entry == NULL)
    {
        pr_info("proc entry could not be created\n");
        return 228;
    }
    printk ("%s - registered proc entry\n", __FUNCTION__);
    INIT_LIST_HEAD(&(fifo.headlist));
    return 0;
}

static void __exit 
task5_exit(void) {
    struct list_head *pos, *q;
    struct fifo_node *item;

    pr_info("hello from task 5: %s\n", __func__);
    list_for_each_safe(pos, q, &(fifo.headlist))
    {
        item = list_entry(pos, struct fifo_node, list);
        list_del(pos);
        vfree(item);
    }
}

module_init(task5_init);
module_exit(task5_exit);
