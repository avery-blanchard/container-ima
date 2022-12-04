#ifndef __VTPM_H__
#define __VTPM_H__

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/ima.h>

#include "container_ima.h"
/*
 * vtpm_pcr_extend 
 * 		vtpm proxy device driver spawns TPM device pair 
 * 			Front end: /dev/tpm<device number>
 *			Back end:  file descriptor returned from ioctl on /dev/vtpmx
 * 		current issue: We spawn the device driver and must interact with front end
 *		while facilitating the backend. idea: spawn a thread to handle to backend?
 * 		each container should see this device as /dev/tpm0 and will have the same interactions
 *
 */
static int vtpm_pcr_extend(struct container_ima_data *data, struct tpm_digest *digests_arg, int pcr)
{
    return tpm_pcr_extend(ima_tpm_chip, 11, digests_arg); //until vTPM is fixed

}
/*
 * container_ima_vtpm_setup 
 *      Set up per container vTPM, PCR 10 for IMA
 * 
 * https://elixir.bootlin.com/linux/latest/source/drivers/char/tpm/tpm_vtpm_proxy.c 
 * https://www.kernel.org/doc/html/v4.13/security/tpm/tpm_vtpm_proxy.html
 * https://elixir.bootlin.com/linux/v6.0.5/source/drivers/char/tpm/tpm_vtpm_proxy.c#L624 
 */
long container_ima_vtpm_setup(struct container_ima_data *data, unsigned int container_id, struct tpm_chip *ima_tpm_chip) 
{
	struct vtpm_proxy_new_dev *new_vtpm;
	long ret;
	int ioctl; 
	struct file *vtpm_file;
	const char *vtpm_fd_name;
	char id[10];
	int fd;
	int check;
	
	new_vtpm = kmalloc(sizeof(struct vtpm_proxy_new_dev), GFP_KERNEL);
	if (!new_vtpm) {
		pr_err("kmalloc failed\n");
	}

	check = sprintf(id, "%d", container_id);
	if (check < 0)
		pr_err("sprintf fails in vtpm setup \n");
	
	check = strcat(vtpm_fd_name, "/dev/vtpm");
	if (check == -1)
		pr_err("strcat fails\n");
	
	check = strcat(vtpm_fd_name, id);
	if (check == -1)
		pr_err("strcat fails\n");

	new_vtpm->flags = VTPM_PROXY_FLAG_TPM2;
	new_vtpm->tpm_num = container_id;
	new_vtpm->fd = vtpm_fd_name;
	new_vtpm->major = MAJOR(ima_tpm_chip->device->devt); // MAJOR(dev_t dev); major number of the TPM device
	new_vtpm->minor = MINOR(ima_tpm_chip->device->devt); // MINOR(dev_t dev); minor number of the TPM device


	ret = ioctl(fd, VTPM_PROXY_IOC_NEW_DEV, vtpm_new_dev);
	
	if (ret != 0) {
		pr_err("Failed to create a new vTPM device\n");
	}

	pr_info("Created TPM device %s; vTPM device has fd %d, "
	       "major/minor = %u/%u.\n",
	       vtpm_fd_name;, fd, new_vtpm.major, vtpm_new_dev.minor);

	data->vtpm = new_vtpm;
	data->vtpmdev = vtpm_fd_name;

	return ret;
	
}
#endif