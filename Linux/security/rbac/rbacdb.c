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

static int next_perm_id = 0;

struct rbac_role *get_role_by_name(char *name)
{
	struct rbac_role *ret;
	list_for_each_entry(ret, &rbac_roles, entry) {
		if (!strcmp(ret->name, name))
			return ret;
	}

	return NULL;
}

struct rbac_permission *get_perm_by_id(int id)
{
	struct rbac_permission *ret;

	if (id < 0)
		return NULL;
	list_for_each_entry(ret, &rbac_perms, entry) {
		if (ret->id == id)
			return ret;
	}

	return NULL;
}

int rbac_add_role(char *name)
{
	struct rbac_role *new_role;
	int ret = 0;

	/* First check if role with name exists */
	if (get_role_by_name(name) != NULL) {
		ret = -EINVAL;
		goto out;
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

int rbac_remove_role(char *name)
{
	struct rbac_role *role;
	int ret = 0;

	/* First check if role with name exists */
	if ((role = get_role_by_name(name)) == NULL) {
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
	rbac_acc_t acc = -1;
	rbac_op_t op = -1;
	rbac_obj_t obj = NULL;
	struct rbac_permission *new_perm;

	/* First parse arguments */
	accp = strsep(args, delim);
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

	opp = strsep(args, delim);
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
	objp = strsep(args, delim);
	if (strlen(objp) == 0)
		obj = NULL;
	else {
		obj = kzalloc(strlen(objp) + 1, GFP_KERNEL);
		if (obj == NULL) {
			ret = -ENOMEM;
			goto out;
		}
		strcpy(obj, objp);
	}

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

int rbac_remove_permission(char *idp, char *delim)
{
	int ret = 0, id;
	struct rbac_permission *perm;

	if (strlen(idp) == 0) {
		ret = -EINVAL;
		goto out;
	}

	/* translate id string to an integer */
	id = simple_strtol(idp, NULL, 10);
	if (id < 0) {
		ret = -EINVAL;
		goto out;
	}

	/* find the removing permission by id */
	if ((perm = get_perm_by_id(id)) == NULL) {
		ret = -EINVAL;
		goto out;
	}

	/* remove the selected permission from the list */
	list_del(&perm->entry);
	kfree(perm);

out:
	return ret;
}
