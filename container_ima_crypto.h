#ifndef __CONTAINER_IMA_CRYPTO_H__
#define __CONTAINER_IMA_CRYPTO_H__

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/ima.h>
#include <linux/integrity.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/ratelimit.h>
#include <linux/file.h>
#include <crypto/hash.h>

#include "container_ima.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima_api.h"

/* default is 0 - 1 page. */
static int ima_maxorder;
static unsigned int ima_bufsize = PAGE_SIZE;
static struct crypto_shash *ima_shash_tfm;
static struct crypto_ahash *ima_ahash_tfm;

static unsigned long ima_ahash_minsize;
module_param_named(ahash_minsize, ima_ahash_minsize, ulong, 0644);
MODULE_PARM_DESC(ahash_minsize, "Minimum file size for ahash use");

/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L39
 */
static int param_set_bufsize(const char *val, const struct kernel_param *kp)
{
	unsigned long long size;
	int order;

	size = memparse(val, NULL);
	order = get_order(size);
	if (order >= MAX_ORDER)
		return -EINVAL;
	ima_maxorder = order;
	ima_bufsize = PAGE_SIZE << order;
	return 0;
}

static const struct kernel_param_ops param_ops_bufsize = {
	.set = param_set_bufsize,
	.get = param_get_uint,
};
#define param_check_bufsize(name, p) __param_check(name, p, unsigned int)

module_param_named(ahash_bufsize, ima_bufsize, bufsize, 0644);
MODULE_PARM_DESC(ahash_bufsize, "Maximum ahash buffer size");

/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L448
 */
static int ima_calc_field_array_hash_tfm(struct ima_field_data *field_data,
					 struct ima_template_desc *td,
					 int num_fields,
					 struct ima_digest_data *hash, struct crypto_shash *tfm)
{
	
	SHASH_DESC_ON_STACK(shash, tfm);
	int rc, i;

	shash->tfm = tfm;
	
	hash->length = crypto_shash_digestsize(tfm);

	rc = crypto_shash_init(shash);
	if (rc != 0)
		return rc;

	for (i = 0; i < num_fields; i++) {
		u8 buffer[IMA_EVENT_NAME_LEN_MAX + 1] = { 0 };
		u8 *data_to_hash = field_data[i].data;
		u32 datalen = field_data[i].len;
		u32 datalen_to_hash =
		    !ima_canonical_fmt ? datalen : cpu_to_le32(datalen);

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
		rc = crypto_shash_final(shash, hash->digest);

	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L100
 */
static void ima_free_tfm(struct crypto_shash *tfm)
{
	if (tfm != ima_shash_tfm)
		crypto_free_shash(tfm);
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L81
 */
static struct crypto_shash *ima_alloc_tfm(enum hash_algo algo)
{
	struct crypto_shash *tfm = ima_shash_tfm;
	int rc;

	if (algo < 0 || algo >= HASH_ALGO__LAST)
		algo = ima_hash_algo;

	if (algo != ima_hash_algo) {
		tfm = crypto_alloc_shash(hash_algo_name[algo], 0, 0);
		if (IS_ERR(tfm)) {
			rc = PTR_ERR(tfm);
			pr_err("Can not allocate %s (reason: %d)\n",
			       hash_algo_name[algo], rc);
		}
	}
	return tfm;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L495
 */
int ima_calc_field_array_hash(struct ima_field_data *field_data,
			      struct ima_template_desc *desc, int num_fields,
			      struct ima_digest_data *hash)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = ima_alloc_tfm(hash->algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = ima_calc_field_array_hash_tfm(field_data, desc, num_fields,
					   hash, tfm);

	ima_free_tfm(tfm);

	return rc;
}
/* 
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L168
 */
static struct crypto_ahash *ima_alloc_atfm(enum hash_algo algo)
{
	struct crypto_ahash *tfm = ima_ahash_tfm;
	int rc;

	if (algo < 0 || algo >= HASH_ALGO__LAST)
		algo = ima_hash_algo;

	if (algo != ima_hash_algo || !tfm) {
		tfm = crypto_alloc_ahash(hash_algo_name[algo], 0, 0);
		if (!IS_ERR(tfm)) {
			if (algo == ima_hash_algo)
				ima_ahash_tfm = tfm;
		} else {
			rc = PTR_ERR(tfm);
			pr_err("Can not allocate %s (reason: %d)\n",
			       hash_algo_name[algo], rc);
		}
	}
	return tfm;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L196
 */
static inline int ahash_wait(int err, struct crypto_wait *wait)
{
	err = crypto_wait_req(err, wait);

	if (err)
		pr_crit_ratelimited("ahash calculation failed: err: %d\n", err);

	return err;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L106
 */
static void *ima_alloc_pages(loff_t max_size, size_t *allocated_size,
			     int last_warn)
{
	void *ptr;
	int order = ima_maxorder;
	gfp_t gfp_mask = __GFP_RECLAIM | __GFP_NOWARN | __GFP_NORETRY;

	if (order)
		order = min(get_order(max_size), order);

	for (; order; order--) {
		ptr = (void *)__get_free_pages(gfp_mask, order);
		if (ptr) {
			*allocated_size = PAGE_SIZE << order;
			return ptr;
		}
	}

	/* order is zero - one page */

	gfp_mask = GFP_KERNEL;

	if (!last_warn)
		gfp_mask |= __GFP_NOWARN;

	ptr = (void *)__get_free_pages(gfp_mask, 0);
	if (ptr) {
		*allocated_size = PAGE_SIZE;
		return ptr;
	}

	*allocated_size = 0;
	return NULL;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L156
 */
static void ima_free_pages(void *ptr, size_t size)
{
	if (!ptr)
		return;
	free_pages((unsigned long)ptr, get_order(size));
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L207
 */
static int ima_calc_file_hash_atfm(struct file *file,
				   struct ima_digest_data *hash,
				   struct crypto_ahash *tfm)
{
	loff_t i_size, offset;
	char *rbuf[2] = { NULL, };
	int rc, read = 0, rbuf_len, active = 0, ahash_rc = 0;
	struct ahash_request *req;
	struct scatterlist sg[1];
	struct crypto_wait wait;
	size_t rbuf_size[2];

	hash->length = crypto_ahash_digestsize(tfm);

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	crypto_init_wait(&wait);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				   CRYPTO_TFM_REQ_MAY_SLEEP,
				   crypto_req_done, &wait);

	rc = ahash_wait(crypto_ahash_init(req), &wait);
	if (rc)
		goto out1;

	i_size = i_size_read(file_inode(file));

	if (i_size == 0)
		goto out2;

	/*
	 * Try to allocate maximum size of memory.
	 * Fail if even a single page cannot be allocated.
	 */
	rbuf[0] = ima_alloc_pages(i_size, &rbuf_size[0], 1);
	if (!rbuf[0]) {
		rc = -ENOMEM;
		goto out1;
	}

	/* Only allocate one buffer if that is enough. */
	if (i_size > rbuf_size[0]) {
		/*
		 * Try to allocate secondary buffer. If that fails fallback to
		 * using single buffering. Use previous memory allocation size
		 * as baseline for possible allocation size.
		 */
		rbuf[1] = ima_alloc_pages(i_size - rbuf_size[0],
					  &rbuf_size[1], 0);
	}

	if (!(file->f_mode & FMODE_READ)) {
		file->f_mode |= FMODE_READ;
		read = 1;
	}

	for (offset = 0; offset < i_size; offset += rbuf_len) {
		if (!rbuf[1] && offset) {
			/* Not using two buffers, and it is not the first
			 * read/request, wait for the completion of the
			 * previous ahash_update() request.
			 */
			rc = ahash_wait(ahash_rc, &wait);
			if (rc)
				goto out3;
		}
		/* read buffer */
		rbuf_len = min_t(loff_t, i_size - offset, rbuf_size[active]);
		rc = integrity_kernel_read(file, offset, rbuf[active],
					   rbuf_len);
		if (rc != rbuf_len)
			goto out3;

		if (rbuf[1] && offset) {
			/* Using two buffers, and it is not the first
			 * read/request, wait for the completion of the
			 * previous ahash_update() request.
			 */
			rc = ahash_wait(ahash_rc, &wait);
			if (rc)
				goto out3;
		}

		sg_init_one(&sg[0], rbuf[active], rbuf_len);
		ahash_request_set_crypt(req, sg, NULL, rbuf_len);

		ahash_rc = crypto_ahash_update(req);

		if (rbuf[1])
			active = !active; /* swap buffers, if we use two */
	}
	/* wait for the last update request to complete */
	rc = ahash_wait(ahash_rc, &wait);
out3:
	if (read)
		file->f_mode &= ~FMODE_READ;
	ima_free_pages(rbuf[0], rbuf_size[0]);
	ima_free_pages(rbuf[1], rbuf_size[1]);
out2:
	if (!rc) {
		ahash_request_set_crypt(req, NULL, hash->digest, 0);
		rc = ahash_wait(crypto_ahash_final(req), &wait);
	}
out1:
	ahash_request_free(req);
	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L190
 */
static void ima_free_atfm(struct crypto_ahash *tfm)
{
	if (tfm != ima_ahash_tfm)
		crypto_free_ahash(tfm);
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L317
 */
static int ima_calc_file_ahash(struct file *file, struct ima_digest_data *hash)
{
	struct crypto_ahash *tfm;
	int rc;

	tfm = ima_alloc_atfm(hash->algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = ima_calc_file_hash_atfm(file, hash, tfm);

	ima_free_atfm(tfm);

	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L333
 */
static int ima_calc_file_hash_tfm(struct file *file,
				  struct ima_digest_data *hash,
				  struct crypto_shash *tfm)
{
	loff_t i_size, offset = 0;
	char *rbuf;
	int rc, read = 0;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;

	hash->length = crypto_shash_digestsize(tfm);

	rc = crypto_shash_init(shash);
	if (rc != 0)
		return rc;

	i_size = i_size_read(file_inode(file));

	if (i_size == 0)
		goto out;

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	if (!(file->f_mode & FMODE_READ)) {
		file->f_mode |= FMODE_READ;
		read = 1;
	}

	while (offset < i_size) {
		int rbuf_len;

		rbuf_len = integrity_kernel_read(file, offset, rbuf, PAGE_SIZE);
		if (rbuf_len < 0) {
			rc = rbuf_len;
			break;
		}
		if (rbuf_len == 0)
			break;
		offset += rbuf_len;

		rc = crypto_shash_update(shash, rbuf, rbuf_len);
		if (rc)
			break;
	}
	if (read)
		file->f_mode &= ~FMODE_READ;
	kfree(rbuf);
out:
	if (!rc)
		rc = crypto_shash_final(shash, hash->digest);
	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L390
 */
static int ima_calc_file_shash(struct file *file, struct ima_digest_data *hash)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = ima_alloc_tfm(hash->algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = ima_calc_file_hash_tfm(file, hash, tfm);

	ima_free_tfm(tfm);

	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L419
 */
int ima_calc_file_hash(struct file *file, struct ima_digest_data *hash)
{
	loff_t i_size;
	int rc;

	/*
	 * For consistency, fail file's opened with the O_DIRECT flag on
	 * filesystems mounted with/without DAX option.
	 */
	if (file->f_flags & O_DIRECT) {
		hash->length = hash_digest_size[ima_hash_algo];
		hash->algo = ima_hash_algo;
		return -EINVAL;
	}

	i_size = i_size_read(file_inode(file));

	if (ima_ahash_minsize && i_size >= ima_ahash_minsize) {
		rc = ima_calc_file_ahash(file, hash);
		if (!rc)
			return 0;
	}

	return ima_calc_file_shash(file, hash);
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L514
 */
static int calc_buffer_ahash_atfm(const void *buf, loff_t len,
				  struct ima_digest_data *hash,
				  struct crypto_ahash *tfm)
{
	struct ahash_request *req;
	struct scatterlist sg;
	struct crypto_wait wait;
	int rc, ahash_rc = 0;

	hash->length = crypto_ahash_digestsize(tfm);

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	crypto_init_wait(&wait);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				   CRYPTO_TFM_REQ_MAY_SLEEP,
				   crypto_req_done, &wait);

	rc = ahash_wait(crypto_ahash_init(req), &wait);
	if (rc)
		goto out;

	sg_init_one(&sg, buf, len);
	ahash_request_set_crypt(req, &sg, NULL, len);

	ahash_rc = crypto_ahash_update(req);

	/* wait for the update request to complete */
	rc = ahash_wait(ahash_rc, &wait);
	if (!rc) {
		ahash_request_set_crypt(req, NULL, hash->digest, 0);
		rc = ahash_wait(crypto_ahash_final(req), &wait);
	}
out:
	ahash_request_free(req);
	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L554
 */
static int calc_buffer_ahash(const void *buf, loff_t len,
			     struct ima_digest_data *hash)
{
	struct crypto_ahash *tfm;
	int rc;

	tfm = ima_alloc_atfm(hash->algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = calc_buffer_ahash_atfm(buf, len, hash, tfm);

	ima_free_atfm(tfm);

	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L571
 */
static int calc_buffer_shash_tfm(const void *buf, loff_t size,
				struct ima_digest_data *hash,
				struct crypto_shash *tfm)
{
	SHASH_DESC_ON_STACK(shash, tfm);
	unsigned int len;
	int rc;

	shash->tfm = tfm;

	hash->length = crypto_shash_digestsize(tfm);

	rc = crypto_shash_init(shash);
	if (rc != 0)
		return rc;

	while (size) {
		len = size < PAGE_SIZE ? size : PAGE_SIZE;
		rc = crypto_shash_update(shash, buf, len);
		if (rc)
			break;
		buf += len;
		size -= len;
	}

	if (!rc)
		rc = crypto_shash_final(shash, hash->digest);
	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L602
 */
static int calc_buffer_shash(const void *buf, loff_t len,
			     struct ima_digest_data *hash)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = ima_alloc_tfm(hash->algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = calc_buffer_shash_tfm(buf, len, hash, tfm);

	ima_free_tfm(tfm);
	return rc;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_crypto.c#L618
 */
int ima_calc_buffer_hash(const void *buf, loff_t len,
			 struct ima_digest_data *hash)
{
	int rc;

	if (ima_ahash_minsize && len >= ima_ahash_minsize) {
		rc = calc_buffer_ahash(buf, len, hash);
		if (!rc)
			return 0;
	}

	return calc_buffer_shash(buf, len, hash);
}
#endif