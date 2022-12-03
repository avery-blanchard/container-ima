/*
 * container_ima_fs.c
 *      Security file system for container measurment lists       
 *
 */
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>
#include <linux/vmalloc.h>
#include <linux/ima.h>
#include "container_ima.h"


static int c_ima_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &c_ima_measurments_seqops);
}
static void *c_ima_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
    struct container_data *data;
    struct ima_queue_entry *qe = v;

    data = ima_data_from_file(m->file);

    rcu_read_lock();
    qe = list_entry_rcu(qe->later.next, struct ima_queue_entry, later);
    rcu_read_unlock();
    (*pos)++;

    return (?qe->later == &data->c_ima_measurements) ? NULL : qe;
}
static ssize_t c_ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos) 
{
    struct container_data *data;
    char tmp[32];
    ssize_t len;
    atomic_long_t *val;

    data = ima_data_from_file(file);
    val = &  &data->hash_tbl.violations;
    len = scnprintf(tmp, sizeof(tmp), "%li\n", atomic_long_read(val));

    return  simple_read_from_buffer(buf, count, ppos, tmp, len);
}

/* use default, adjust later if needed (probably needed) */
static const struct file_operations c_ima_measurements_ops = {
	.open = c_ima_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/* operations for ascii file, try to use IMA's seq_ops*/
static const struct seq_operations c_ima_ascii_measurements_seqops = {
	.start = ima_measurements_start,
	.next = c_ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_ascii_measurements_show
};


static const struct file_operations c_ima_htable_violations_ops = {
	.read = c_ima_show_htable_violations,
	.llseek = generic_file_llseek,
};

/*
 * container_ima_fs_init
 * 		Securityfs
 *      Create a secure place to store per container measurement logs
 * 		Idea: under /integrity/ima/containers/ have a directory per container named with container id
 *      	
 */
int container_ima_fs_init(struct container_ima_data *data, static struct dentry c_ima_dir, static struct dentry c_ima_symlink) 
{
	int res;
	char *dir_name = "integrity/ima/container/";
	char *id;

	sprintf(id, "%s", container_id);
	strcat(dir_name, id);

	data->container_dir = securityfs_create_dir("container_ima", dir_name);
	if (IS_ERR(data->container_dir))
		return -1;

	data->binary_runtime_measurements =
	securityfs_create_file("binary_runtime_measurements",
				   S_IRUSR | S_IRGRP, data->container_dir, NULL,
				   &c_ima_measurements_ops);

	if (IS_ERR(data->binary_runtime_measurements)) {
		ret = PTR_ERR(data->binary_runtime_measurements);
		goto out;
	}

	data->ascii_runtime_measurements =
	    securityfs_create_file("ascii_runtime_measurements",
				   S_IRUSR | S_IRGRP, data->container_dir, NULL,
				   &c_ima_ascii_measurements_ops);
	if (IS_ERR(data->ascii_runtime_measurements)) {
		ret = PTR_ERR(data->ascii_runtime_measurements);
		goto out;
	}

	data->runtime_measurements_count =
	    securityfs_create_file("runtime_measurements_count",
				   S_IRUSR | S_IRGRP,data->container_dir, NULL,
				   &ima_measurements_count_ops);
	if (IS_ERR(data->runtime_measurements_count)) {
		ret = PTR_ERR(data->runtime_measurements_count);
		goto out;
	}

	data->violations =
	    securityfs_create_file("violations", S_IRUSR | S_IRGRP,
				   data->container_dir, NULL, &c_ima_htable_violations_ops);
	if (IS_ERR(data->violations)) {
		ret = PTR_ERR(data->violations);
		goto out;
    }
    
	data->c_ima_policy = securityfs_create_file("policy", POLICY_FILE_FLAGS,
					    data->container_dir, NULL,
					    &ima_measure_policy_ops);
	if (IS_ERR(data->c_ima_policy)) {
		ret = PTR_ERR(data->c_ima_policy);
		goto out;
	}
    
	return 0;
out:
	securityfs_remove(data->c_ima_policy);
	securityfs_remove(data->violations);
	securityfs_remove(data->runtime_measurements_count);
	securityfs_remove(data->ascii_runtime_measurements);
	securityfs_remove(data->binary_runtime_measurements);
	securityfs_remove(data->container_dir);

	return res;
}