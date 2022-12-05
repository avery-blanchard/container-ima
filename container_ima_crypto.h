#ifndef __CONTAINER_IMA_CRYPTO_H__
#define __CONTAINER_IMA_CRYPTO_H__

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ima.h>
#include <linux/integrity.h>

#include "container_ima.h"
#include "container_ima.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima.h"

static int ima_calc_field_array_hash_tfm(struct ima_field_data *field_data,
					 struct ima_template_entry *entry,
					 int tfm_idx)
{
	SHASH_DESC_ON_STACK(shash, ima_algo_array[tfm_idx].tfm);
	struct ima_template_desc *td = entry->template_desc;
	int num_fields = entry->template_desc->num_fields;
	int rc, i;

	shash->tfm = ima_algo_array[tfm_idx].tfm;

	rc = crypto_shash_init(shash);
	if (rc != 0)
		return rc;

	for (i = 0; i < num_fields; i++) {
		u8 buffer[IMA_EVENT_NAME_LEN_MAX + 1] = { 0 };
		u8 *data_to_hash = field_data[i].data;
		u32 datalen = field_data[i].len;
		u32 datalen_to_hash = !ima_canonical_fmt ?
				datalen : (__force u32)cpu_to_le32(datalen);

		if (strcmp(td->name, IMA_TEMPLATE_IMA_NAME) != 0) {
			rc = crypto_shash_update(shash,
						(const u8 *) &datalen_to_hash,
						sizeof(datalen_to_hash));
			if (rc)
				break;
		} else if (strcmp(td->fields[i]->field_id, "n") == 0) {
			memcpy(buffer, data_to_hash, datalen);
			data_to_hash = buffer;
			datalen = IMA_EVENT_NAME_LEN_MAX + 1;
		}
		rc = crypto_shash_update(shash, data_to_hash, datalen);
		if (rc)
			break;
	}

	if (!rc)
		rc = crypto_shash_final(shash, entry->digests[tfm_idx].digest);

	return rc;
}

int ima_calc_field_array_hash(struct ima_field_data *field_data,
			      struct ima_template_entry *entry)
{
	u16 alg_id;
	int rc, i;

	rc = ima_calc_field_array_hash_tfm(field_data, entry, ima_sha1_idx);
	if (rc)
		return rc;

	entry->digests[ima_sha1_idx].alg_id = TPM_ALG_SHA1;

	for (i = 0; i < NR_BANKS(ima_tpm_chip) + ima_extra_slots; i++) {
		if (i == ima_sha1_idx)
			continue;

		if (i < NR_BANKS(ima_tpm_chip)) {
			alg_id = ima_tpm_chip->allocated_banks[i].alg_id;
			entry->digests[i].alg_id = alg_id;
		}

		/* for unmapped TPM algorithms digest is still a padded SHA1 */
		if (!ima_algo_array[i].tfm) {
			memcpy(entry->digests[i].digest,
			       entry->digests[ima_sha1_idx].digest,
			       TPM_DIGEST_SIZE);
			continue;
		}

		rc = ima_calc_field_array_hash_tfm(field_data, entry, i);
		if (rc)
			return rc;
	}
	return rc;
}
#endif