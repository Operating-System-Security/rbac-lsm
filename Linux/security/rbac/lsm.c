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
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include "rbac.h"

#define RBAC_NAME "rbac"

static LIST_HEAD(rbac_roles);
static LIST_HEAD(rbac_perms);
static int next_perm_id = 0;
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
	/* add security hooks */
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
	RBAC_ROLE,
	RBAC_PERM,
	RBAC_FP_TYPE_NUM,
} rbac_fp_type_t;
static struct dentry *rbac_dir = NULL;
static struct dentry *rbac_fp[RBAC_FP_TYPE_NUM];

static int rbac_add_role(char *name)
{
	struct rbac_role *new_role, *role;
	int ret = 0;

	/* First check if role with name exists */
	list_for_each_entry(role, &rbac_roles, entry) {
		if (!strcmp(role->name, name)) {
			pr_info("rbac: role with name \"%s\" already exists!", name);
			ret = -EINVAL;
			goto out;
		}
	}

	/* Second alloc memory space for the new role */
	new_role = kzalloc(sizeof(struct rbac_role), GFP_KERNEL);
	if (new_role == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* Finally initialize the new role */
	strcpy(new_role->name, name);
	/* we do not initialize perms[] field because we use kzalloc */
	list_add_tail(&new_role->entry, &rbac_roles);

out:
	return ret;
}

static int rbac_remove_role(char *name)
{
	struct rbac_role *role;
	int ret = 0;

	/* First check if role with name exists */
	list_for_each_entry(role, &rbac_roles, entry) {
		if (!strcmp(role->name, name)) {
			break;
		}
	}
	if (list_entry_is_head(role, &rbac_roles, entry)) {
		ret = -EINVAL;
		goto out;
	}

	/* Second remove the selected role from the list */
	list_del(&role->entry);

	/* Finally free memory space of the removed role */
	kfree(role);

out:
	return ret;
}

int rbac_add_permission(char **args, char *delim)
{
	int ret = 0;
	char *accp, *opp, *objp;
	acceptablity_t acc = -1;
	operation_t op = -1;
	object_t obj = NULL;
	struct rbac_permission *new_perm;

	/* First parse arguments */
	if (args == NULL) {
		ret = -EINVAL;
		goto out;
	}
	accp = strsep(args, delim);
	pr_info("%s", accp);
	switch (accp[0]) {
	case 'a':
		if (strcmp(accp, "accept") && strcmp(accp, "a")) {
			ret = -EINVAL;
			goto out;
		}
		acc = ACC_ACCEPT;
		break;
	case 'd':
		if (strcmp(accp, "deny") && strcmp(accp, "d")) {
			ret = -EINVAL;
			goto out;
		}
		acc = ACC_DENY;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (args == NULL) {
		ret = -EINVAL;
		goto out;
	}
	opp = strsep(args, delim);
	pr_info("%s", opp);
	switch (opp[0]) {
	case 'r':
		if (strcmp(opp, "read") && strcmp(opp, "r")) {
			ret = -EINVAL;
			goto out;
		}
		op = OP_READ;
		break;
	case 'w':
		if (strcmp(opp, "write") && strcmp(opp, "w")) {
			ret = -EINVAL;
			goto out;
		}
		op = OP_WRITE;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (args == NULL) {
		ret = -EINVAL;
		goto out;
	}
	objp = strsep(args, delim);
	pr_info("%s", objp);
	obj = kzalloc(strlen(objp) + 1, GFP_KERNEL);
	if (obj == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	strcpy(obj, objp);

	/* Then allocate new permission and initialize it */
	new_perm = kzalloc(sizeof(struct rbac_permission), GFP_KERNEL);
	if (new_perm == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	new_perm->id = next_perm_id++;
	new_perm->acc = acc;
	new_perm->op = op;
	new_perm->obj = obj;

	/* add the new permission to the list */
	list_add_tail(&new_perm->entry, &rbac_perms);

out:
	return ret;
}

static int rbac_remove_permission(char **args, char *delim)
{
	return 0;
}

static ssize_t rbac_enable_read(struct file *file, char __user *buf,
				size_t size, loff_t *ppos)
{
	char kbuf[40];

	sprintf(kbuf, "rbac: %s\n", rbac_enable ? "enabled" : "disabled");
	return simple_read_from_buffer(buf, size, ppos, kbuf, strlen(kbuf));
}

static ssize_t rbac_enable_write(struct file *file, const char __user *buf,
				 size_t size, loff_t * ppos)
{
	char kbuf[20];
	int ret;
	
	ret = simple_write_to_buffer(kbuf, 20, ppos, buf, size);
	if (ret < 0)
		goto out;

	switch (kbuf[0]) {
	case '0':
		rbac_enable = 0;
		break;
	case '1':
		rbac_enable = 1;
		break;
	default:
		ret = -EINVAL;
	}

out:
	return ret;
}

static ssize_t rbac_role_read(struct file *file, char __user *buf,
			      size_t size, loff_t *ppos)
{
	char* kbuf;
	int off = 0, ret = 0, i;
	struct rbac_role *role;

	kbuf = kzalloc(1024, GFP_KERNEL);
	if (kbuf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	list_for_each_entry(role, &rbac_roles, entry) {
		off += sprintf(kbuf + off, "%s", role->name);
		for (i = 0; i < ROLE_MAX_PERMS; i++) {
			if (role->perms[i] != NULL)
				off += sprintf(kbuf + off, "perm[%d]", i);
		}
		off += sprintf(kbuf + off, "\n");
	}
	ret = simple_read_from_buffer(buf, size, ppos, kbuf, strlen(kbuf));
	kfree(kbuf);

out:
	return ret;
}

static ssize_t rbac_role_write(struct file *file, const char __user *buf,
			       size_t size, loff_t * ppos)
{
	char kbuf[40], delim[] = " \n";
	char *kbufp, *token;
	int ret, err;

	ret = simple_write_to_buffer(kbuf, 40, ppos, buf, size);
	if (ret < 0)
		goto out;
	
	kbufp = kbuf;
	token = strsep(&kbufp, delim);
	switch (token[0]) {
	case 'a': /* add a role with name */
		if (!strcmp(token, "add") || !strcmp(token, "a")) {
			token = strsep(&kbufp, delim);
			err = rbac_add_role(token);
			if (err < 0)
				ret = err;
		} else {
			ret = -EINVAL;
		}
		break;
	case 'r': /* remove a role with name */
		if (!strcmp(token, "remove") || !strcmp(token, "r")) {
			token = strsep(&kbufp, delim);
			err = rbac_remove_role(token);
			if (err < 0)
				ret = err;
		} else {
			ret = -EINVAL;
		}
		break;
	default:
		ret = -EINVAL;
	}

out:
	return ret;
}

static ssize_t rbac_perm_read(struct file *file, char __user *buf,
			      size_t size, loff_t *ppos)
{
	char* kbuf;
	int off = 0, ret = 0;
	struct rbac_permission *perm;

	kbuf = kzalloc(1024, GFP_KERNEL);
	if (kbuf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	list_for_each_entry(perm, &rbac_perms, entry) {
		off += sprintf(kbuf + off, "[%d]: %s %s on %s\n",
			       perm->id, acceptability_name[perm->acc],
			       operation_name[perm->op], perm->obj);
	}
	ret = simple_read_from_buffer(buf, size, ppos, kbuf, strlen(kbuf));
	kfree(kbuf);

out:
	return ret;
}

static ssize_t rbac_perm_write(struct file *file, const char __user *buf,
			       size_t size, loff_t * ppos)
{
	char kbuf[40], delim[] = " \n";
	char *kbufp, *token;
	int ret, err;

	ret = simple_write_to_buffer(kbuf, 40, ppos, buf, size);
	if (ret < 0)
		goto out;
	
	kbufp = kbuf;
	token = strsep(&kbufp, delim);
	switch (token[0]) {
	case 'a': /* add a permission with args */
		if (!strcmp(token, "add") || !strcmp(token, "a")) {
			err = rbac_add_permission(&kbufp, delim);
			if (err < 0)
				ret = err;
		} else {
			ret = -EINVAL;
		}
		break;
	case 'r': /* remove a permission with id */
		if (!strcmp(token, "remove") || !strcmp(token, "r")) {
			err = rbac_remove_permission(&kbufp, delim);
			if (err < 0)
				ret = err;
		} else {
			ret = -EINVAL;
		}
		break;
	default:
		ret = -EINVAL;
	}

out:
	return ret;
}

static const struct file_operations rbac_ops[RBAC_FP_TYPE_NUM] = {
	[RBAC_ENABLE] = {
		.read = rbac_enable_read,
		.write = rbac_enable_write,
	},
	[RBAC_ROLE] = {
		.read = rbac_role_read,
		.write = rbac_role_write,
	},
	[RBAC_PERM] = {
		.read = rbac_perm_read,
		.write = rbac_perm_write,
	}
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

	dentryp = rbac_fp[RBAC_ROLE] =
	       securityfs_create_file("role", 0660, rbac_dir,
				      NULL, &rbac_ops[RBAC_ROLE]);
	if (IS_ERR(dentryp)) {
		ret = PTR_ERR(dentryp);
		goto out;
	}

	dentryp = rbac_fp[RBAC_PERM] =
	       securityfs_create_file("perm", 0660, rbac_dir,
				      NULL, &rbac_ops[RBAC_PERM]);
	if (IS_ERR(dentryp)) {
		ret = PTR_ERR(dentryp);
		goto out;
	}

out:
	return ret;
}

fs_initcall(rbac_fs_init)
