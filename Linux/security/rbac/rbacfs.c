// SPDX-License-Identifier: GPL-2.0-only
/*
 * A Role Based Access Control LSM
 *
 * Copyright 2024 Miao Hao <haomiao19@mails.ucas.ac.cn>
 */
#include "linux/namei.h"
#include <asm-generic/errno-base.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/list.h>
#include <linux/lsm_hooks.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include "rbac.h"

LIST_HEAD(rbac_users);
LIST_HEAD(rbac_roles);
LIST_HEAD(rbac_perms);

typedef enum {
	RBAC_ENABLE,
	RBAC_USER,
	RBAC_ROLE,
	RBAC_PERM,
	RBAC_CTRL,
	RBAC_FP_TYPE_NUM,
} rbac_fp_type_t;
typedef int (*rbac_ctrl_op_t)(int wr, char **args);
struct rbac_file {
	struct dentry			*fp;
	const struct file_operations	ops;
	const char			*namep;
	const umode_t			mode;
};
static struct dentry *rbac_dir = NULL;

static int rbac_user_op(int wr, char **args)
{
	char *uidp;
	uid_t uid;
	int ret = 0;

	if (rbac_get_nargs(args, 1, &uidp) != 1) {
		return -EINVAL;
	}
	/* translate id string to an integer */
	uid = simple_strtol(uidp, NULL, 10);
	if (uid < 0) {
		return -EINVAL;
	}

	switch(wr) {
	case 0:
		ret = rbac_add_user(uid);
		break;
	case 1:
		ret = rbac_remove_user(uid);
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

static int rbac_role_op(int wr, char **args)
{
	char *name;
	int ret = 0;

	if (rbac_get_nargs(args, 1, &name) != 1) {
		return -EINVAL;
	}
	switch(wr) {
	case 0:
		ret = rbac_add_role(name);
		break;
	case 1:
		ret = rbac_remove_role(name);
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

static int rbac_perm_op(int wr, char **args)
{
	char *tokens[3], *accp, *opp, *objp, *obj_path;
	int ret = 0, id, obj_path_len;
	rbac_acc_t acc = -1;
	rbac_op_t op = -1;
	rbac_obj_t obj = NULL;
	struct path path;

	switch(wr) {
	case 0:
		/* First parse args */
		if (rbac_get_nargs(args, 3, tokens) < 2) {
			ret = -EINVAL;
			goto out;
		}
		accp = tokens[0];
		opp = tokens[1];
		objp = tokens[2];

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

		/* we accept no obj path input, it means "for all objects" */
		if (objp == NULL || strlen(objp) == 0) {
			obj_path_len = 2;
		} else {
			obj_path_len = strlen(objp) + 1;
		}

		obj_path = kzalloc(obj_path_len, GFP_KERNEL);
		if (obj_path == NULL) {
			ret = -ENOMEM;
			goto out;
		}
		if (objp == NULL || strlen(objp) == 0) {
			obj_path[0] = '/';
			obj_path[1] = '\0';
		} else
			strcpy(obj_path, objp);

		ret = kern_path(obj_path, LOOKUP_FOLLOW, &path);
		if (ret)
			goto out;
		obj = d_inode(path.dentry);
		ret = rbac_add_permission(acc, op, obj, obj_path);
		break;
	case 1:
		if (rbac_get_nargs(args, 1, tokens) != 1) {
			ret = -EINVAL;
			goto out;
		}
		/* translate id string to an integer */
		id = simple_strtol(tokens[0], NULL, 10);
		if (id < 0) {
			ret = -EINVAL;
			goto out;
		}
		ret = rbac_remove_permission(id);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static int rbac_bind_op(int wr, char **args)
{
	char *tokens[2], *name;
	int id, ret = 0;

	if (rbac_get_nargs(args, 2, tokens) != 2) {
		ret = -EINVAL;
		goto out;
	}

	id = simple_strtol(tokens[0], NULL, 10);
	if (id < 0) {
		ret = -EINVAL;
		goto out;
	}
	name = tokens[1];

	switch (wr) {
	case 0:
		ret = rbac_bind_permission(id, name);
		break;
	case 1:
		ret = rbac_unbind_permission(id, name);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static int rbac_register_op(int wr, char **args)
{
	char *tokens[2], *name;
	int ret = 0, num_args;
	uid_t uid;

	num_args = rbac_get_nargs(args, 2, tokens);
	if ((num_args != 2 && wr == 0) || (num_args != 1 && wr == 1)) {
		ret = -EINVAL;
		goto out;
	}

	uid = simple_strtol(tokens[0], NULL, 10);
	if (uid < 0) {
		ret = -EINVAL;
		goto out;
	}
	name = tokens[1];

	switch (wr) {
	case 0:
		ret = rbac_register_user(uid, name);
		break;
	case 1:
		ret = rbac_unregister_user(uid);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static const rbac_ctrl_op_t rbac_ctrl_ops[] = {
	[RBAC_USER] = rbac_user_op,
	[RBAC_ROLE] = rbac_role_op,
	[RBAC_PERM] = rbac_perm_op,
};

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

static ssize_t rbac_user_read(struct file *file, char __user *buf,
			      size_t size, loff_t *ppos)
{
	char* kbuf;
	int ret = 0;

	kbuf = kzalloc(1024, GFP_KERNEL);
	if (kbuf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	rbac_get_users_info(kbuf);
	ret = simple_read_from_buffer(buf, size, ppos, kbuf, strlen(kbuf));
	kfree(kbuf);

out:
	return ret;
}

static ssize_t rbac_role_read(struct file *file, char __user *buf,
			      size_t size, loff_t *ppos)
{
	char* kbuf;
	int ret = 0;

	kbuf = kzalloc(1024, GFP_KERNEL);
	if (kbuf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	rbac_get_roles_info(kbuf);
	ret = simple_read_from_buffer(buf, size, ppos, kbuf, strlen(kbuf));
	kfree(kbuf);

out:
	return ret;
}

static ssize_t rbac_perm_read(struct file *file, char __user *buf,
			      size_t size, loff_t *ppos)
{
	char* kbuf;
	int ret = 0;

	kbuf = kzalloc(1024, GFP_KERNEL);
	if (kbuf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	rbac_get_perms_info(kbuf);
	ret = simple_read_from_buffer(buf, size, ppos, kbuf, strlen(kbuf));
	kfree(kbuf);

out:
	return ret;
}

static ssize_t rbac_ctrl_write(struct file *file, const char __user *buf,
			       size_t size, loff_t * ppos)
{
	char kbuf[40];
	char *args, *tokens[10];
	int ret, wr = -1, err;
	rbac_fp_type_t type = -1;

	ret = simple_write_to_buffer(kbuf, 40, ppos, buf, size);
	if (ret < 0)
		goto out;

	/* First we pares the object of the ctrl operation */
	args = kbuf;
	if (rbac_get_nargs(&args, 1, tokens) != 1) {
		ret = -EINVAL;
		goto out;
	}
	switch (tokens[0][0]) {
	case 'a':
		if (!strcmp(tokens[0], "a") || !strcmp(tokens[0], "add")) {
			wr = 0;
		} else {
			ret = -EINVAL;
			goto out;
		}
		break;
	case 'b':
		if (!strcmp(tokens[0], "b") || !strcmp(tokens[0], "bind")) {
			err = rbac_bind_op(0, &args);
			if (err < 0)
				ret = err;
			goto out;
		} else {
			ret = -EINVAL;
			goto out;
		}
		break;
	case 'r':
		if (!strcmp(tokens[0], "r") || !strcmp(tokens[0], "remove")) {
			wr = 1;
		} else if (!strcmp(tokens[0], "register")) {
			err = rbac_register_op(0, &args);
			if (err < 0)
				ret = err;
			goto out;
		} else {
			ret = -EINVAL;
			goto out;
		}
		break;
	case 'u':
		if (!strcmp(tokens[0], "u") || !strcmp(tokens[0], "unbind")) {
			err = rbac_bind_op(1, &args);
			if (err < 0)
				ret = err;
			goto out;
		} else if (!strcmp(tokens[0], "unregister")) {
			err = rbac_register_op(1, &args);
			if (err < 0)
				ret = err;
			goto out;
		} else {
			ret = -EINVAL;
			goto out;
		}
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (rbac_get_nargs(&args, 1, tokens) != 1) {
		ret = -EINVAL;
		goto out;
	}
	switch (tokens[0][0]) {
	case 'p':
		if (!strcmp(tokens[0], "p") || !strcmp(tokens[0], "perm")) {
			type = RBAC_PERM;
		} else {
			ret = -EINVAL;
			goto out;
		}
		break;
	case 'r':
		if (!strcmp(tokens[0], "r") || !strcmp(tokens[0], "role")) {
			type = RBAC_ROLE;
		} else {
			ret = -EINVAL;
			goto out;
		}
		break;
	case 'u':
		if (!strcmp(tokens[0], "u") || !strcmp(tokens[0], "user")) {
			type = RBAC_USER;
		} else {
			ret = -EINVAL;
			goto out;
		}
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if(rbac_ctrl_ops[type] != NULL) {
		err = rbac_ctrl_ops[type](wr, &args);
		if (err < 0)
			ret = err;
	}
	
out:
	return ret;
}

#define INIT_RBAC_RDWR_FILE(name, type)			\
	[type] = {					\
		.ops = {				\
			.read = rbac_##name##_read,	\
			.write = rbac_##name##_write,	\
		},					\
		.namep = #name,				\
		.mode = 0660,				\
	}
#define INIT_RBAC_RDON_FILE(name, type)			\
	[type] = {					\
		.ops = {				\
			.read = rbac_##name##_read,	\
		},					\
		.namep = #name,				\
		.mode = 0440,				\
	}
#define INIT_RBAC_WRON_FILE(name, type)			\
	[type] = {					\
		.ops = {				\
			.write = rbac_##name##_write,	\
		},					\
		.namep = #name,				\
		.mode = 0220,				\
	}

static struct rbac_file rbac_files[] = {
	INIT_RBAC_RDWR_FILE(enable, RBAC_ENABLE),
	INIT_RBAC_RDON_FILE(user, RBAC_USER),
	INIT_RBAC_RDON_FILE(role, RBAC_ROLE),
	INIT_RBAC_RDON_FILE(perm, RBAC_PERM),
	INIT_RBAC_WRON_FILE(ctrl, RBAC_CTRL),
};

static int __init rbac_fs_init(void)
{
	int ret = 0, i;

	rbac_dir = securityfs_create_dir(RBAC_NAME, NULL);
	if (IS_ERR(rbac_dir)) {
		ret = PTR_ERR(rbac_dir);
		goto out;
	}

	for (i = RBAC_ENABLE; i < RBAC_FP_TYPE_NUM; i++) {
		rbac_files[i].fp =
			securityfs_create_file(rbac_files[i].namep,
					       rbac_files[i].mode, rbac_dir,
					       NULL, &rbac_files[i].ops);
		if (IS_ERR(rbac_files[i].fp)) {
			ret = PTR_ERR(rbac_files[i].fp);
			goto out;
		}
	}

out:
	return ret;
}

fs_initcall(rbac_fs_init)
