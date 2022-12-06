/*
 * File: container_ima_init.c
 *      Functions for initialization and cleanup
 */
#ifndef __CONTAINER_IMA_INIT_H__
#define __CONTAINER_IMA_INIT_H__

#include <linux/ima.h>
#include <linux/hugetlb.h>
#include <linux/vtpm_proxy.h>
#include <linux/bpf.h>
#include <linux/spinlock.h>
#include <linux/integrity.h>
#include "ebpf/bpf_helpers.h"
#include "container_ima.h"
#include "container_ima.h"
#include "container_ima.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima_api.h"

#define MMAP_MAX_MAPPINGS 100 //adjust as needed

struct tpm_chip *ima_tpm_chip;
static struct kmem_cache *c_ima_cache;

/*
 * init_container_ima_data
 * 	
 */
struct container_ima_data *init_container_ima_data(unsigned int container_id) 
{
	struct container_ima_data *data;

	/* init policy lists */
	INIT_LIST_HEAD(&data->c_ima_default_rules);
	INIT_LIST_HEAD(&data->c_ima_policy_rules);

	data->c_ima_rules = (struct list_head __rcu *)(&data->c_ima_rules);
	data->container_id = container_id;

	/* init hash table */
	atomic_long_set(&data->c_ima_write_mutex.owner, 0);
	atomic_long_set(&data->hash_tbl->violations, 0);
	memset(&data->hash_tbl->queue, 0, sizeof(data->hash_tbl));

	/* init ML */
	INIT_LIST_HEAD(&data->c_ima_measurements);
	mutex_init(&data->c_ima_write_mutex);
	
	data->valid_policy = 1;
	data->c_ima_fs_flags = 0;

	data->container_integrity_iint_tree = RB_ROOT;
	//DEFINE_RWLOCK(data->container_integrity_iint_lock);

	return data;
}
struct container_ima_data *create_container_ima_data(void) 
{
	struct container_ima_data *data;

	data = kmem_cache_zalloc(c_ima_cache, GFP_KERNEL);
	if (!data) {
		return ERR_PTR(-ENOMEM);
		pr_err("Allocation failed in cache\n");
	}
	return data;
}
void container_ima_free_data(struct container_ima_data *data)
{
	/* Free policy, tree, hash table, vtpm, etc.... here */
	kmem_cache_free(c_ima_cache, data);

}
/*
 * container_ima_init
 * 		Initalize container IMA
 * 		Create vTPM proxy using container_id as its number
 *		Create measurment log 
 * 		Default policy
 */
struct container_ima_data *init_container_ima(unsigned int container_id, static struct dentry *c_ima_dir, static struct dentry *c_ima_symlink) 
{
	int ret;
	struct container_ima_data *data;
	/* check if container exist, then return container_data here */
	data = ima_data_exists(container_id);
	if (data)
		return data;

	data = init_container_ima_data(container_id);

	ima_tpm_chip = tpm_default_chip();
	if (!ima_tpm_chip)
		pr_info("No TPM chip found, activating TPM-bypass!\n");


	//ret = container_ima_vtpm_setup(data, container_id, ima_tpm_chip); // per container vTPM

	ret = container_ima_fs_init(data, c_ima_dir, c_ima_symlink);
	//ret = integrity_init_keyring(INTEGRITY_KEYRING_IMA); // per container key ring

	//data->keyring = INTEGRITY_KEYRING_IMA;

	if (ret)
		return ret;
	
	//ret = container_ima_crypto_init(data); // iterate over PCR banks and init the algorithms per bank  

	return data;
}

/*
 * container_keyring_init 
 * 
 * https://man7.org/linux/man-pages/man7/keyrings.7.html
 * https://man7.org/linux/man-pages/man2/add_key.2.html 
 */
int container_keyring_init()
{
	return 0;
}
/*
 * TODO
 */
int container_ima_cleanup() {
	
	return 0;
}
/*
 * container_ima_crypto_init
 * 
 * Iterate over PCRs, check algorithm for PCR10 and record
 */
int container_ima_crypto_init(struct container_ima_data *data)
{
	int ret;
	int i;


	return 0;

}
/*
 * create_mmap_bpf_map
 * https://elixir.boo lin.com/linux/v4.14.135/source/tools/lib/bpf/bpf.c#L83
 * https://man7.org/linux/man-pages/man2/bpf.2.html
 */
int create_mmap_bpf_map(void) 
{
	int ret;
	int key_size = (int) sizeof(uint64_t);
	int value_size = sizeof(struct mmap_args_t);

	return bpf_create_map(BPF_MAP_TYPE_ARRAY, key_size, value_size, MMAP_MAX_MAPPINGS, 0, -1);


}
/*
 * mmap_bpf_map_add
 * https://elixir.bootlin.com/linux/v4.14.135/source/tools/lib/bpf/bpf.c#L170
 */
static long mmap_bpf_map_add(uint64_t id, struct mmap_args_t *args, int map_fd)
{
	return bpf_map_update_elem(map_fd, &id, (void *)args, 0);

}
/*
 * mmap_bpf_map_lookup 
 * https://elixir.bootlin.com/linux/v4.14.135/source/tools/lib/bpf/bpf.c#L184 
 */
static long mmap_bpf_map_lookup(uint64_t id, struct mmap_args_t *args, int map_fd)
{
	args = bpf_map_lookup_elem(map_fd, &id);
	return bpf_map_delete_elem(&map_fd, &id);
}
#endif