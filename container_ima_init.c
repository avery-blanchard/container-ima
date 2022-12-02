/*
 * File: container_ima_init.c
 *      Functions for initialization and cleanup
 */
#include <linux/ima.h>

#include "container_ima.h"

struct tpm_chip *ima_tpm_chip;
static struct rb_root container_integrity_iint_tree = RB_ROOT;
static DEFINE_RWLOCK(container_integrity_iint_lock);

/*
 * container_ima_vtpm_setup 
 *      Set up per container vTPM, PCR 10 for IMA
 * 
 * https://elixir.bootlin.com/linux/latest/source/drivers/char/tpm/tpm_vtpm_proxy.c 
 * https://www.kernel.org/doc/html/v4.13/security/tpm/tpm_vtpm_proxy.html
 * https://elixir.bootlin.com/linux/v6.0.5/source/drivers/char/tpm/tpm_vtpm_proxy.c#L624 
 */
long container_ima_vtpm_setup(int container_id, struct tpm_chip *ima_tpm_chip, struct container_data *data) 
{
	struct vtpm_proxy_new_dev *new_vtpm;
	long ret;
	int ioctl; 
	struct file *vtpm_file;
	const char *vtpm_fd_name;
	char id[10];
	int check;
	
	new_vtpm = kmalloc(sizeof(struct vtpm_proxy_new_dev), GFP_KERNEL);
	if (!new_vtpm) {
		pr_err("kmalloc failed\n");
	}

	check = sprintf(id, "%d", container_id);
	if (check < 0)
		pr_err("sprintf fails in vtpm setup \n");
	
	check = strcat_s("/dev/vtpm", id);
	if (check == -1)
		pr_err("strcat_s fails in vtpm setup\n");

	new_vtpm.flags = VTPM_PROXY_FLAG_TPM2;
	new_vtpm.tpm_num = container_id;
	new_vtpm.fd = "/dev/vtpm";
	new_vtpm.major = MAJOR(ima_tpm_chip->device->devt); // MAJOR(dev_t dev); major number of the TPM device
	new_vtp.minor = MINOR(ima_tpm_chip->device->devt); // MINOR(dev_t dev); minor number of the TPM device


	ret = vtpmx_ioc_new_dev(vtpm_file, ioctl, (unsigned long)&new_vtpm);
	
	if (ret != 0) {
		pr_err("Failed to create a new vTPM device\n");
	}

	data->vtpm = new_vtpm;
	return ret;
	
}
struct container_ima_data *init_container_ima_data(int container_id) 
{
	struct container_ima_data *data;

	/* init policy lists */
	INIT_LIST_HEAD(&data->c_ima_default_rules);
	INIT_LIST_HEAD(&data->c_ima_policy_rules);

	data->c_ima_rules = (struct list_head __rcu *)(&data->c_ima_rules);
	
	/* init hash table */
	atomic_long_set(&data->hashc_ima_write_mutex_tbl.len, 0);
	atomic_long_set(&data->hash_tbl.violations, 0);
	memset(&data->hash_tbl.queue, 0, sizeof(data->hash_tbl));

	/* init ML */
	INIT_LIST_HEAD(&data->c_ima_measurements);
	mutex_init(&data->c_ima_write_mutex);
	
	data->valid_policy = 1;
	data->c_ima_fs_flags = 0;

	return data;
}
/*
 * container_ima_init
 * 		Initalize container IMA
 * 		Create vTPM proxy using container_id as its number
 *		Create measurment log 
 * 		Default policy 
 */
int container_ima_init(int container_id) 
{
	int ret;
	struct container_ima_data *data;

	data = kmalloc(size_of(struct container_data), GFP_KERNEL);
	if (!data) {
		pr_error("kmalloc failed\n");
		return -1;
	}
	ima_tpm_chip = tpm_default_chip();
	if (!ima_tpm_chip)
		pr_info("No TPM chip found, activating TPM-bypass!\n");


	container_ima_vtpm = container_ima_vtpm_setup(container_id, ima_tpm_chip, data); // per container vTPM
 
	data = init_container_ima_data(container_id);
	//ret = integrity_init_keyring(INTEGRITY_KEYRING_IMA); // per container key ring

	//data->keyring = INTEGRITY_KEYRING_IMA;

	if (ret)
		return ret;
	ret = container_ima_crypto_init(data); // iterate over PCR banks and init the algorithms per bank  

	if (ret)
		return ret;

	ret = container_ima_ml_init(data); // set up directory for per container Measurment Log

	if (ret) 
		return ret;

	container_ima_policy_init(data); // start with default policy for all containers

	return ret;
}

/*
 * container_ima_fs_init
 *      Create a secure place to store per container measurement logs
 */
int container_ima_fs_init() 
{
	int res;
	mode_t dir_mode= 0755;

	res = mkdir(measure_log_dir, dir_mode);

	return res;
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
 * container_ima_setup
 *
 * Set up environment to initalize container IMA
 * Malloc structure to hold container ids and other data to preserve state
 */
void container_ima_setup()
{
	ima_hash_setup();

}
/*
 * container_ima_crypto_init
 * 
 * Iterate over PCRs, check algorithm for PCR10 and record
 */
int container_ima_crypto_init(struct container_data *data)
{
	int ret;
	int i;


	return 0;

}