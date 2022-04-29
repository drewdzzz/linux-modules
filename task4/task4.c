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
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static void 
list_vma(void) {
    struct task_struct *cur_task = current;
    int cur_pid = cur_task->pid;
    struct vm_area_struct *cur_area = cur_task->mm->mmap;
    while (cur_area->vm_prev != NULL) {
        cur_area = cur_area->vm_prev;
    }
    while (cur_area != NULL) {
        pr_info("VMA for pid %d: %lx .. %lx", cur_pid, 
                cur_area->vm_start, cur_area->vm_end);
        cur_area = cur_area->vm_next;
    }
}

static int 
va_to_pa(unsigned long addr) {
    pgd_t *pgd = pgd_offset(current->mm, addr);

    pr_info("va_to_pa for %lx\n", addr);

    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        pr_info(" pgd = empty or bad\n");
        return -1;
    }

    p4d_t *p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
            pr_info("  p4d = empty or bad\n");
            return -1;
    }
    
    pud_t *pud = pud_offset(p4d, addr);
    pr_info(" pgd = %lx\n", pgd_val(*pgd));

    if (pud_none(*pud) || pud_bad(*pud)) {
        pr_info("   pud = empty or bad\n");
        return -1;
    }
    pr_info("  pud = %lx\n", pud_val(*pud));

    pmd_t *pmd = pmd_offset(pud, addr);

    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        pr_info("    pmd = empty or bad\n");
        return -1;
    }
    if (pmd_trans_huge(*pmd)) {
        pr_info("    pmd = trans_huge\n");
        return -1;
    }

    pte_t *pte = pte_offset_map(pmd, addr);
    pr_info("    pmd = %lx\n", pmd_val(*pmd));

    if (pte_none(*pte)) {
        pr_info("     pte = empty\n");
        return -1;
    }
    pr_info("     pte = %lx\n", pte_val(*pte));
    unsigned long page_addr = pte_val(*pte) & PAGE_MASK;
    unsigned long page_offset = addr & ~PAGE_MASK;
    unsigned long paddr = page_addr | page_offset;
    pr_info("     paddr = %lx\n", paddr);
    pte_unmap(pte);
    return 0;
}

#define MAX_LEN 30
static char *read_buffer;

static int 
process_query(size_t len) 
{
    unsigned long addr = 0;
    int read = 0;

    if (len >= 7 && strncmp(read_buffer, "listvma", 7) == 0) {
        list_vma();
        return 0;
    } else if (len >= 8 && strncmp(read_buffer, "findpage", 8) == 0) {
        read_buffer[len] = 0;
        read = sscanf(read_buffer, "findpage %lx", &addr);
        if (read == 0)
            return -228;
        return va_to_pa(addr);
    }
    return -229;
}

ssize_t 
my_write(struct file *file, const char __user * buf, size_t count, loff_t * ppos)
{
    int rc = 0;

    if (count > MAX_LEN) {
        pr_err("Module task 4 - read: count is bigger than %d", MAX_LEN);
        return 225;
    }
    if (copy_from_user(read_buffer, buf, count))
        return -EFAULT;

    rc = process_query(count);
    if (rc)
        return rc;
    return count;
}

int 
my_open(struct inode *inode, struct  file *file) {
  return single_open(file, NULL, NULL);
}

static struct proc_dir_entry *proc_entry;

static const struct proc_ops proc_fops = {
 .proc_write = my_write,
 .proc_open = my_open,
 .proc_release = single_release,
};

static int __init
task4_init(void) {
    pr_info("hello from task 4: %s\n", __func__);
    proc_entry = proc_create("mmaneg", 0, NULL, &proc_fops);
    if (proc_entry == NULL)
    {
        pr_info("proc entry could not be created\n");
        return 228;
    }
    read_buffer = vmalloc(MAX_LEN + 1);
    read_buffer[MAX_LEN] = 0;
    if (read_buffer == NULL) {
        remove_proc_entry("mmaneg", proc_entry);
        return -1;
    }
    printk ("%s - registered proc entry\n", __FUNCTION__);
    return 0;
}

static void __exit 
task4_exit(void) {
    remove_proc_entry("mmaneg", proc_entry);
    vfree(read_buffer);
    pr_info("hello from task 4: %s\n", __func__);
}

module_init(task4_init);
module_exit(task4_exit);
