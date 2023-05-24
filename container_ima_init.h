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
#include "container_ima.h"
#include "container_ima.h"
#include "container_ima.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima_api.h"

#define MMAP_MAX_MAPPINGS 100 //adjust as needed

struct tpm_chip *ima_tpm_chip;
static struct kmem_cache *c_ima_cache;
struct ima_rule_entry container_ima_rules = {.action = MEASURE, .mask = MAY_EXEC, .flags = IMA_FUNC | IMA_MASK};
int ima_hash_algo;

int container_ima_crypto_init(void) {

	ima_tpm_chip = tpm_default_chip();
        
	if (!ima_tpm_chip) {
                pr_info("No TPM chip found, activating TPM-bypass!\n");
		ima_hash_algo = 0x1;
		return 0;
	}

	ima_hash_algo = ima_tpm_chip->allocated_banks[10].crypto_id;

	return 0;
}
/*
 * TODO
 */
int container_ima_cleanup() {
	
	return 0;
}
#endif
