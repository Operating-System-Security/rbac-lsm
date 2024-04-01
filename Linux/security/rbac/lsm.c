// SPDX-License-Identifier: GPL-2.0-only
/*
 * A Role Based Accessment Control LSM
 *
 * Copyright 2024 Miao Hao <haomiao19@mails.ucas.ac.cn>
 */
#include <asm-generic/errno-base.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define RBAC_NAME "rbac"

static int rbac_enable = IS_ENABLED(CONFIG_SECURITY_RBAC);

static int example_inode_permission(struct inode *inode, int mask)
{
	// printk("hello, rbac!");
	return 0;
}
 
static struct security_hook_list rbac_hooks[] = {
	LSM_HOOK_INIT(inode_permission, example_inode_permission),
};

static int __init rbac_init(void)
{
	security_add_hooks(rbac_hooks, ARRAY_SIZE(rbac_hooks), RBAC_NAME);
	pr_info("rbac: initialized and enabled.\n");
	return 0;
}

DEFINE_LSM(rbac) = {
	.name = RBAC_NAME,
	.init = rbac_init,
	.enabled = &rbac_enable,
};

typedef enum {
	RBAC_ENABLE,
	RBAC_FP_TYPE_NUM,
} rbac_fp_type_t;
static struct dentry *rbac_dir = NULL;
static struct dentry *rbac_fp[RBAC_FP_TYPE_NUM];

static ssize_t rbac_enable_read (struct file *file, char __user *buf,
				 size_t size, loff_t *ppos)
{
	char kbuf[40];
	sprintf(kbuf, "rbac: %s\n", rbac_enable ? "enabled" : "disabled");
	return simple_read_from_buffer(buf, size, ppos, kbuf, strlen(kbuf));
}

static ssize_t rbac_enable_write (struct file *file, const char __user *buf,
				  size_t size, loff_t * ppos)
{
	char kbuf[40];
	int ret = simple_write_to_buffer(kbuf, 40, ppos, buf, size);
	switch (kbuf[0]) {
	case '0':
		rbac_enable = 0;
		break;
	case '1':
		rbac_enable = 1;
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

static const struct file_operations rbac_ops[RBAC_FP_TYPE_NUM] = {
	[RBAC_ENABLE] = {
		.read = rbac_enable_read,
		.write = rbac_enable_write,
	},
};

static int __init rbac_fs_init(void)
{
	int ret = 0;
	struct dentry *dentryp;
	dentryp = rbac_dir = securityfs_create_dir(RBAC_NAME, NULL);
	if (IS_ERR(dentryp)) {
		ret = PTR_ERR(dentryp);
		goto out;
	}
	dentryp = rbac_fp[RBAC_ENABLE] = 
	       securityfs_create_file("enable", 0660, rbac_dir,
				      NULL, &rbac_ops[RBAC_ENABLE]);
	if (IS_ERR(dentryp)) {
		ret = PTR_ERR(dentryp);
		goto out;
	}

out:
	return ret;
}

fs_initcall(rbac_fs_init)
