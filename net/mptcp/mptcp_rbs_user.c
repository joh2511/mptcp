#include "mptcp_rbs_user.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_parser.h"
#include "mptcp_rbs_sched.h"
#include "mptcp_rbs_scheduler.h"
#include <../fs/proc/internal.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/workqueue.h>

struct rbs_dir;

struct rbs_sub_dir {
	struct rbs_sub_dir *next;
	struct mptcp_rbs_scheduler *scheduler;
	struct proc_dir_entry *dir;
};

struct rbs_dir {
	struct rbs_dir *next;
	struct proc_dir_entry *dir;
	struct rbs_sub_dir *first_sub_dir;
};

static struct rbs_dir *first_rbs_dir = NULL;
static DEFINE_MUTEX(delete_mutex);
static struct mptcp_rbs_scheduler *schedulers_to_delete = NULL;

static void link_rbs_sub_dir(struct rbs_dir *dir, struct rbs_sub_dir *sub_dir)
{
	sub_dir->next = dir->first_sub_dir;
	dir->first_sub_dir = sub_dir;
}

static void unlink_rbs_sub_dir(struct rbs_dir *dir, struct rbs_sub_dir *sub_dir)
{
	struct rbs_sub_dir *tmp = dir->first_sub_dir;
	struct rbs_sub_dir *prev = NULL;

	while (tmp != sub_dir) {
		if (!tmp)
			return;

		prev = tmp;
		tmp = tmp->next;
	}

	if (!prev)
		dir->first_sub_dir = sub_dir->next;
	else
		prev->next = sub_dir->next;

	sub_dir->next = NULL;
}

static void link_rbs_dir(struct rbs_dir *dir)
{
	dir->next = first_rbs_dir;
	first_rbs_dir = dir;
}

static void unlink_rbs_dir(struct rbs_dir *dir)
{
	struct rbs_dir *tmp = first_rbs_dir;
	struct rbs_dir *prev = NULL;

	while (tmp != dir) {
		if (!tmp)
			return;

		prev = tmp;
		tmp = tmp->next;
	}

	if (!prev)
		first_rbs_dir = dir->next;
	else
		prev->next = dir->next;

	dir->next = NULL;
}

static void link_scheduler_to_delete(struct mptcp_rbs_scheduler *scheduler)
{
	struct mptcp_rbs_scheduler *tmp;

	mutex_lock(&delete_mutex);

	/* Check if the scheduler is already in the list */
	tmp = schedulers_to_delete;
	while (tmp) {
		if (tmp == scheduler)
			break;
		tmp = tmp->next;
	}

	if (tmp != scheduler) {
		scheduler->next = schedulers_to_delete;
		schedulers_to_delete = scheduler;
	}

	mutex_unlock(&delete_mutex);
}

static bool create_scheduler_sub_dir(struct rbs_dir *rbs_dir,
				     struct mptcp_rbs_scheduler *scheduler);
static void remove_scheduler_sub_dir(struct rbs_dir *rbs_dir,
				     struct mptcp_rbs_scheduler *scheduler);

static void delete_scheduler(struct work_struct *work)
{
	struct mptcp_rbs_scheduler *scheduler;
	struct rbs_dir *rbs_dir;

	mutex_lock(&delete_mutex);

	while (schedulers_to_delete) {
		scheduler = schedulers_to_delete->next;

		/* Delete the proc entries for the scheduler in all rbs
		 * directories
		 */
		rbs_dir = first_rbs_dir;
		while (rbs_dir) {
			remove_scheduler_sub_dir(rbs_dir, schedulers_to_delete);
			rbs_dir = rbs_dir->next;
		}

		/* Remove the CFG */
		mptcp_rbs_scheduler_free(schedulers_to_delete);

		schedulers_to_delete = scheduler;
	}

	mutex_unlock(&delete_mutex);
}

static DECLARE_WORK(delete_task, delete_scheduler);

/*
 * info proc entry
 */

static int info_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Number of OOO advanced hits %u\n", mptcp_ooo_number_matches);

	return 0;
}

static int info_open(struct inode *inode, struct file *file)
{
	return single_open(file, info_show, PDE_DATA(inode));
}

static const struct file_operations info_file_ops = {
	.owner = THIS_MODULE,
	.open = info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * schedulers proc entry
 */

static int schedulers_show(struct seq_file *seq, void *v)
{
	const struct mptcp_rbs_scheduler *scheduler =
	    mptcp_rbs_scheduler_get_registered();

	seq_printf(seq, "id: scheduler name\n");
	while (scheduler) {
		seq_printf(seq, "%p: %s\n", scheduler, scheduler->name);
		scheduler = scheduler->next;
	}

	return 0;
}

static int schedulers_open(struct inode *inode, struct file *file)
{
	return single_open(file, schedulers_show, PDE_DATA(inode));
}

struct strbuffer {
	char *start;
	int len;
};

static ssize_t schedulers_write(struct file *file, const char __user *buf,
				size_t size, loff_t *offset)
{
	struct strbuffer *buffer =
	    ((struct seq_file *) file->private_data)->private;

	if (!size)
		return 0;

	if (buffer) {
		char *new_start =
		    krealloc(buffer->start, buffer->len + size + 1, GFP_ATOMIC);
		if (!new_start) {
			printk("RBS: Could not allocate memory for scheduler "
			       "code\n");
			return -1;
		}

		buffer->start = new_start;
	} else {
		buffer = kmalloc(sizeof(struct strbuffer), GFP_KERNEL);
		if (!buffer) {
			printk("RBS: Could not allocate memory for scheduler "
			       "code\n");
			return -1;
		}

		buffer->len = 0;
		buffer->start = kmalloc(size + 1, GFP_KERNEL);
		if (!buffer->start) {
			kfree(buffer);
			printk("RBS: Could not allocate memory for scheduler "
			       "code\n");
			return -1;
		}
	}
	((struct seq_file *) file->private_data)->private = buffer;

	buffer->start[buffer->len + size] = 0;
	copy_from_user(&buffer->start[buffer->len], buf, size);
	buffer->len += size;

	return size;
}

static int schedulers_release(struct inode *inode, struct file *file)
{
	struct strbuffer *buffer =
	    ((struct seq_file *) file->private_data)->private;
	struct mptcp_rbs_scheduler *scheduler;
	struct rbs_dir *rbs_dir;

	if (!buffer)
		return 0;

	/* Parse the scheduler */
	scheduler = mptcp_rbs_scheduler_parse(buffer->start);
	kfree(buffer->start);
	kfree(buffer);
	if (!scheduler)
		return -1;

	/* Optimize the scheduler */
	if (mptcp_rbs_opts_enabled) {
		mptcp_rbs_optimize(&scheduler->variations[0], &scheduler->del,
				   0, false);
	}

	/* Add the scheduler */
	if (!strcmp(scheduler->name, "info") ||
	    !strcmp(scheduler->name, "schedulers") ||
	    !strcmp(scheduler->name, "default") ||
	    !mptcp_rbs_scheduler_register(scheduler)) {
		mptcp_rbs_scheduler_free(scheduler);
		return -2;
	}

	/* Create the proc entries for the scheduler in every rbs directory */
	rbs_dir = first_rbs_dir;
	while (rbs_dir) {
		create_scheduler_sub_dir(rbs_dir, scheduler);
		rbs_dir = rbs_dir->next;
	}

	return 0;
}

static const struct file_operations schedulers_file_ops = {
	.owner = THIS_MODULE,
	.open = schedulers_open,
	.read = seq_read,
	.write = schedulers_write,
	.llseek = seq_lseek,
	.release = schedulers_release,
};

/*
 * default proc entry
 */

static int default_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%s\n", mptcp_rbs_scheduler_get_default()->name);

	return 0;
}

static int default_open(struct inode *inode, struct file *file)
{
	return single_open(file, default_show, PDE_DATA(inode));
}

static ssize_t default_write(struct file *file, const char __user *buf,
			     size_t size, loff_t *offset)
{
	char *str;
	char *trimmed_str;
	struct mptcp_rbs_scheduler *scheduler = NULL;
	const struct mptcp_rbs_scheduler *tmp =
	    mptcp_rbs_scheduler_get_registered();

	if (size == 0)
		return 0;

	str = kzalloc(size + 1, GFP_KERNEL);
	copy_from_user(str, buf, size);
	trimmed_str = strim(str);

	/* Find scheduler with the given name */
	while (tmp) {
		if (!strcmp(trimmed_str, tmp->name)) {
			scheduler = (struct mptcp_rbs_scheduler *) tmp;
			break;
		}

		tmp = tmp->next;
	}
	kfree(str);

	if (!scheduler)
		return -1;

	mptcp_rbs_scheduler_set_default(scheduler);
	return size;
}

static const struct file_operations default_file_ops = {
	.owner = THIS_MODULE,
	.open = default_open,
	.read = seq_read,
	.write = default_write,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * opt proc entry
 */

int mptcp_rbs_opts_enabled =
#ifdef CONFIG_MPTCP_RBSOPT
#ifdef CONFIG_MPTCP_RBSEBPF
    2
#else
    1
#endif
#else
    0
#endif
    ;

static int opt_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%d\n", mptcp_rbs_opts_enabled);
	return 0;
}

static int opt_open(struct inode *inode, struct file *file)
{
	return single_open(file, opt_show, PDE_DATA(inode));
}

static ssize_t opt_write(struct file *file, const char __user *buf, size_t size,
			 loff_t *offset)
{
	char *str;
	char *trimmed_str;

	if (size == 0)
		return 0;

	str = kzalloc(size + 1, GFP_KERNEL);
	copy_from_user(str, buf, size);
	trimmed_str = strim(str);

	if (!strcmp(trimmed_str, "0"))
		mptcp_rbs_opts_enabled = 0;
#ifdef CONFIG_MPTCP_RBSOPT
	else if (!strcmp(trimmed_str, "1"))
		mptcp_rbs_opts_enabled = 1;
#ifdef CONFIG_MPTCP_RBSEBPF
	else if (!strcmp(trimmed_str, "2"))
		mptcp_rbs_opts_enabled = 2;
#endif
#endif
	else
		return -1;

	return size;
}

static const struct file_operations opt_file_ops = {
	.owner = THIS_MODULE,
	.open = opt_open,
	.read = seq_read,
	.write = opt_write,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * measurements proc entry for default and round robin scheduler
 */

extern u64 total_default_time_skb;
extern u64 total_default_time_no_skb;
extern u64 total_default_count_skb;
extern u64 total_default_count_no_skb;

extern u64 total_rr_time_skb;
extern u64 total_rr_time_no_skb;
extern u64 total_rr_count_skb;
extern u64 total_rr_count_no_skb;

static int measurements2_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Default:\n");
	seq_printf(seq, "     state    executions          time\n");

#ifdef CONFIG_MPTCP_RBSMEASURE
	seq_printf(seq, "    no_skb %13llu %13llu\n",
		   total_default_count_no_skb, total_default_time_no_skb);
	seq_printf(seq, "       skb %13llu %13llu\n", total_default_count_skb,
		   total_default_time_skb);
#endif

	seq_printf(seq, "\n");
	seq_printf(seq, "Round Robin:\n");
	seq_printf(seq, "     state    executions          time\n");

#ifdef CONFIG_MPTCP_RBSMEASURE
	seq_printf(seq, "    no_skb %13llu %13llu\n", total_rr_count_no_skb,
		   total_rr_time_no_skb);
	seq_printf(seq, "       skb %13llu %13llu\n", total_rr_count_skb,
		   total_rr_time_skb);
#endif

	return 0;
}

static int measurements2_open(struct inode *inode, struct file *file)
{
	return single_open(file, measurements2_show, PDE_DATA(inode));
}

static ssize_t measurements2_write(struct file *file, const char __user *buf,
				   size_t size, loff_t *offset)
{
	char *str;
	char *trimmed_str;
	bool b;

	if (size == 0)
		return 0;

	str = kzalloc(size + 1, GFP_KERNEL);
	copy_from_user(str, buf, size);
	trimmed_str = strim(str);

	/* Check if value == "0" */
	if (!strtobool(trimmed_str, &b) && !b) {
#ifdef CONFIG_MPTCP_RBSMEASURE
		total_default_time_skb = 0;
		total_default_time_no_skb = 0;
		total_default_count_skb = 0;
		total_default_count_no_skb = 0;

		total_rr_time_skb = 0;
		total_rr_time_no_skb = 0;
		total_rr_count_skb = 0;
		total_rr_count_no_skb = 0;
#endif
		kfree(str);
		return size;
	}
	kfree(str);

	return -1;
}

static const struct file_operations measurements2_file_ops = {
	.owner = THIS_MODULE,
	.open = measurements2_open,
	.read = seq_read,
	.write = measurements2_write,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * delete proc entry (per scheduler)
 */

static int delete_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "0\n");

	return 0;
}

static int delete_open(struct inode *inode, struct file *file)
{
	return single_open(file, delete_show, PDE_DATA(inode));
}

static ssize_t delete_write(struct file *file, const char __user *buf,
			    size_t size, loff_t *offset)
{
	struct mptcp_rbs_scheduler *scheduler =
	    ((struct seq_file *) file->private_data)->private;
	char *str;
	char *trimmed_str;
	bool b;

	if (size == 0)
		return 0;

	str = kzalloc(size + 1, GFP_KERNEL);
	copy_from_user(str, buf, size);
	trimmed_str = strim(str);

	/* Check if value == "1" */
	if (!strtobool(trimmed_str, &b) && b) {
		scheduler->del = true;
		kfree(str);
		return size;
	}
	kfree(str);

	return -1;
}

static int delete_release(struct inode *inode, struct file *file)
{
	struct mptcp_rbs_scheduler *scheduler = PDE_DATA(inode);
	int result = single_release(inode, file);

	if (scheduler->del) {
		/* Check if the scheduler is in use */
		if (scheduler->usage > 0 ||
		    scheduler == mptcp_rbs_scheduler_get_default()) {
			/* Cannot delete the scheduler */
			scheduler->del = false;
		} else {
			/* Remove the scheduler from usable ones */
			mptcp_rbs_scheduler_unregister(scheduler);

			/* Put the scheduler in the queue of schedulers to
			 * delete
			 */
			link_scheduler_to_delete(scheduler);

			/* Schedule the delete task because we cannot delete the
			 * delete proc entry here
			 */
			schedule_work(&delete_task);
		}
	}

	return result;
}

static const struct file_operations delete_file_ops = {
	.owner = THIS_MODULE,
	.open = delete_open,
	.read = seq_read,
	.write = delete_write,
	.llseek = seq_lseek,
	.release = delete_release,
};

/*
 * dump proc entry (per scheduler)
 */

static int dump_show(struct seq_file *seq, void *v)
{
	const struct mptcp_rbs_scheduler *scheduler = seq->private;
	int len = 0;
	int variation_count = 0;
	int i;
	int pos;
	char *str;

	for (i = 0; i < MPTCP_RBS_VARIATION_COUNT; ++i) {
		if (!scheduler->variations[i].first_block)
			break;

		len += strlen("Subflows :\n") + (i > 9 ? 2 : 1) + 1 +
		       mptcp_rbs_scheduler_print(scheduler, i, NULL);
		++variation_count;
	}

	str = kzalloc(len + 1, GFP_KERNEL);
	if (!str) {
		seq_printf(seq, "\n");
		return 0;
	}

	pos = 0;
	for (i = 0; i < variation_count; ++i) {
		pos += sprintf(&str[pos], "Subflows %d:\n",
			       scheduler->variations[i].sbf_num);
		pos += mptcp_rbs_scheduler_print(scheduler, i, &str[pos]);
		pos += sprintf(&str[pos], "\n");
	}

	seq_printf(seq, "%s", str);
	kfree(str);

	return 0;
}

static int dump_open(struct inode *inode, struct file *file)
{
	return single_open(file, dump_show, PDE_DATA(inode));
}

static const struct file_operations dump_file_ops = {
	.owner = THIS_MODULE,
	.open = dump_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * measurements proc entry (per scheduler)
 */

static int measurements_show(struct seq_file *seq, void *v)
{
	const struct mptcp_rbs_scheduler *scheduler = seq->private;
#ifdef CONFIG_MPTCP_RBSMEASURE
	int i;
#endif

	seq_printf(seq, "  subflows    executions          time\n");

#ifdef CONFIG_MPTCP_RBSMEASURE
	for (i = 0; i < MPTCP_RBS_VARIATION_COUNT; ++i) {
		if (!scheduler->variations[i].first_block)
			break;

		seq_printf(seq, "%10d %13llu %13llu\n",
			   scheduler->variations[i].sbf_num,
			   scheduler->variations[i].exec_count,
			   scheduler->variations[i].total_time);
	}
#endif

	seq_printf(seq, "\n");
	seq_printf(seq, "     state    executions          time\n");

#ifdef CONFIG_MPTCP_RBSMEASURE
	seq_printf(seq, "noa_no_skb %13llu %13llu\n",
		   scheduler->total_count_noa_no_skb,
		   scheduler->total_time_noa_no_skb);
	seq_printf(seq, "   noa_skb %13llu %13llu\n",
		   scheduler->total_count_noa_skb,
		   scheduler->total_time_noa_skb);
	seq_printf(seq, "    oa_skb %13llu %13llu\n",
		   scheduler->total_count_oa_skb, scheduler->total_time_oa_skb);
	seq_printf(seq, "execno_skb %13llu %13llu\n",
		   scheduler->total_exec_count_no_skb,
		   scheduler->total_exec_time_no_skb);
	seq_printf(seq, "  exec_skb %13llu %13llu\n",
		   scheduler->total_exec_count_skb,
		   scheduler->total_exec_time_skb);
#endif

	return 0;
}

/*
 * scheduler info proc entry (per scheduler)
 */

static int scheduler_info_show(struct seq_file *seq, void *v)
{
	const struct mptcp_rbs_scheduler *scheduler = seq->private;

	seq_printf(seq, "Total bytes sent %llu\n", scheduler->total_bytes_sent);
	return 0;
}

static int measurements_open(struct inode *inode, struct file *file)
{
	return single_open(file, measurements_show, PDE_DATA(inode));
}

static ssize_t measurements_write(struct file *file, const char __user *buf,
				  size_t size, loff_t *offset)
{
	struct mptcp_rbs_scheduler *scheduler =
	    ((struct seq_file *) file->private_data)->private;
	char *str;
	char *trimmed_str;
	bool b;
#ifdef CONFIG_MPTCP_RBSMEASURE
	int i;
#endif

	if (size == 0)
		return 0;

	str = kzalloc(size + 1, GFP_KERNEL);
	copy_from_user(str, buf, size);
	trimmed_str = strim(str);

	/* Check if value == "0" */
	if (!strtobool(trimmed_str, &b) && !b) {
#ifdef CONFIG_MPTCP_RBSMEASURE
		for (i = 0; i < MPTCP_RBS_VARIATION_COUNT; ++i) {
			if (!scheduler->variations[i].first_block)
				break;

			scheduler->variations[i].exec_count = 0;
			scheduler->variations[i].total_time = 0;
		}

		scheduler->total_count_noa_no_skb = 0;
		scheduler->total_time_noa_no_skb = 0;
		scheduler->total_count_noa_skb = 0;
		scheduler->total_time_noa_skb = 0;
		scheduler->total_count_oa_skb = 0;
		scheduler->total_time_oa_skb = 0;
		scheduler->total_exec_count_no_skb = 0;
		scheduler->total_exec_time_no_skb = 0;
		scheduler->total_exec_count_skb = 0;
		scheduler->total_exec_time_skb = 0;
#endif
		kfree(str);
		return size;
	}
	kfree(str);

	return -1;
}

static const struct file_operations measurements_file_ops = {
	.owner = THIS_MODULE,
	.open = measurements_open,
	.read = seq_read,
	.write = measurements_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int scheduler_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, scheduler_info_show, PDE_DATA(inode));
}

static const struct file_operations scheduler_info_file_ops = {
	.owner = THIS_MODULE,
	.open = scheduler_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static bool create_scheduler_sub_dir(struct rbs_dir *rbs_dir,
				     struct mptcp_rbs_scheduler *scheduler)
{
	struct proc_dir_entry *dir;
	struct rbs_sub_dir *rbs_sub_dir;

	dir = proc_mkdir(scheduler->name, rbs_dir->dir);
	if (!dir)
		return false;

	rbs_sub_dir = kmalloc(sizeof(struct rbs_sub_dir), GFP_KERNEL);
	rbs_sub_dir->scheduler = scheduler;
	rbs_sub_dir->dir = dir;
	link_rbs_sub_dir(rbs_dir, rbs_sub_dir);

	mutex_lock(&delete_mutex);
	proc_create_data("delete", S_IRUGO, dir, &delete_file_ops, scheduler);
	proc_create_data("dump", S_IRUGO, dir, &dump_file_ops, scheduler);
	proc_create_data("measurements", S_IRUGO, dir, &measurements_file_ops,
			 scheduler);
	proc_create_data("info", S_IRUGO, dir, &scheduler_info_file_ops, scheduler);
	mutex_unlock(&delete_mutex);

	return true;
}

static void remove_scheduler_sub_dir(struct rbs_dir *rbs_dir,
				     struct mptcp_rbs_scheduler *scheduler)
{
	struct rbs_sub_dir *rbs_sub_dir = rbs_dir->first_sub_dir;

	while (rbs_sub_dir) {
		if (rbs_sub_dir->scheduler == scheduler) {
			remove_proc_entry("delete", rbs_sub_dir->dir);
			remove_proc_entry("dump", rbs_sub_dir->dir);
			remove_proc_entry("measurements", rbs_sub_dir->dir);
			remove_proc_entry("info", rbs_sub_dir->dir);
			remove_proc_entry(scheduler->name, rbs_dir->dir);

			unlink_rbs_sub_dir(rbs_dir, rbs_sub_dir);
			kfree(rbs_sub_dir);
			break;
		}

		rbs_sub_dir = rbs_sub_dir->next;
	}
}

static int init_subsys(struct net *net)
{
#ifndef NS3
	struct rbs_dir *rbs_dir;
	struct proc_dir_entry *dir;
	struct mptcp_rbs_scheduler *scheduler;

	rbs_dir = kmalloc(sizeof(struct rbs_dir), GFP_KERNEL);

	dir = proc_mkdir_data("rbs", 0, net->mptcp.proc_net_mptcp, rbs_dir);
	if (!dir) {
		kfree(rbs_dir);
		return -ENOMEM;
	}

	if (!proc_create_data("info", S_IRUGO, dir, &info_file_ops, net)) {
		remove_proc_entry("rbs", net->mptcp.proc_net_mptcp);
		kfree(rbs_dir);
		return -ENOMEM;
	}

	if (!proc_create_data("schedulers", S_IRUGO, dir, &schedulers_file_ops,
			      NULL)) {
		remove_proc_entry("info", dir);
		remove_proc_entry("rbs", net->mptcp.proc_net_mptcp);
		kfree(rbs_dir);
		return -ENOMEM;
	}

	if (!proc_create("default", S_IRUGO, dir, &default_file_ops)) {
		remove_proc_entry("schedulers", dir);
		remove_proc_entry("info", dir);
		remove_proc_entry("rbs", net->mptcp.proc_net_mptcp);
		kfree(rbs_dir);
		return -ENOMEM;
	}

	if (!proc_create("opt", S_IRUGO, dir, &opt_file_ops)) {
		remove_proc_entry("schedulers", dir);
		remove_proc_entry("info", dir);
		remove_proc_entry("default", dir);
		remove_proc_entry("rbs", net->mptcp.proc_net_mptcp);
		kfree(rbs_dir);
		return -ENOMEM;
	}

	if (!proc_create("measurements", S_IRUGO, dir,
			 &measurements2_file_ops)) {
		remove_proc_entry("schedulers", dir);
		remove_proc_entry("info", dir);
		remove_proc_entry("default", dir);
		remove_proc_entry("opt", dir);
		remove_proc_entry("rbs", net->mptcp.proc_net_mptcp);
		kfree(rbs_dir);
		return -ENOMEM;
	}

	rbs_dir->dir = dir;
	rbs_dir->first_sub_dir = NULL;
	link_rbs_dir(rbs_dir);
	net->mptcp.proc_net_mptcp_rbs = dir;

	scheduler = mptcp_rbs_scheduler_get_registered();
	while (scheduler) {
		create_scheduler_sub_dir(rbs_dir, scheduler);
		scheduler = scheduler->next;
	}
#endif

	return 0;
}

static void exit_subsys(struct net *net)
{
#ifndef NS3
	struct rbs_dir *rbs_dir;
	struct mptcp_rbs_scheduler *scheduler;

	if (!net->mptcp.proc_net_mptcp_rbs)
		return;

	rbs_dir = net->mptcp.proc_net_mptcp_rbs->data;

	scheduler = mptcp_rbs_scheduler_get_registered();
	while (scheduler) {
		remove_scheduler_sub_dir(rbs_dir, scheduler);
		scheduler = scheduler->next;
	}

	remove_proc_entry("info", rbs_dir->dir);
	remove_proc_entry("schedulers", rbs_dir->dir);
	remove_proc_entry("default", rbs_dir->dir);
	remove_proc_entry("opt", rbs_dir->dir);
	remove_proc_entry("measurements", rbs_dir->dir);
	remove_proc_entry("rbs", net->mptcp.proc_net_mptcp);
	net->mptcp.proc_net_mptcp_rbs = NULL;

	unlink_rbs_dir(rbs_dir);
	kfree(rbs_dir);
#endif
}

static struct pernet_operations proc_ops = {
	.init = init_subsys,
	.exit = exit_subsys,
};

bool mptcp_rbs_user_interface_init(void)
{
	return !register_pernet_subsys(&proc_ops);
}
