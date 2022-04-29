#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <asm/atomic.h>

MODULE_LICENSE("GPL");

static atomic_t counter, stopped;
static int my_dev_id, irq = 1, timeout_sec = 5;
static int timeout_jiffies = 0;

static void 
timeout_cb(struct work_struct *work);
static DECLARE_DELAYED_WORK(click_stats_work, timeout_cb); 

void 
timeout_cb(struct work_struct *work)
{
    if (atomic_read(&stopped) == 1)
        return;
    int cur_cnt = atomic_xchg(&counter, 0); 
    /* Divide by 2 because irq_handler is called on press and on release. */
    cur_cnt /= 2;
    pr_info("Keyboard clicks in last %d seconds: %d", timeout_sec, cur_cnt);
    schedule_delayed_work(&click_stats_work, timeout_jiffies);
}

static irqreturn_t 
irq_handler(int irq, void *dev_id) 
{
    (void) irq;
    (void) dev_id;
    atomic_inc(&counter);
    return IRQ_HANDLED;
}

static int __init task2_init(void) {
    int rc;
    atomic_set(&counter, 0);
    atomic_set(&stopped, 0);
    timeout_jiffies = msecs_to_jiffies(timeout_sec * 1000);
    pr_info("hello from task2: %s\n", __func__);
    rc = request_irq(irq, irq_handler, IRQF_SHARED, "KeyboardCounter", &my_dev_id);
    if (rc) {
        pr_err("request_irq() failed: %d\n", rc);
        return 228;
    }
    pr_info("irq has been planted\n");
    schedule_delayed_work(&click_stats_work, timeout_jiffies);
    return 0;
}

static void __exit task2_exit(void) {
    synchronize_irq(irq);
    free_irq(irq, &my_dev_id);

    atomic_set(&stopped, 1);
    cancel_delayed_work_sync(&click_stats_work);
    pr_info("hello from task2: %s\n", __func__);
}

module_init(task2_init);
module_exit(task2_exit);
