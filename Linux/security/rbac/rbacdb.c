// SPDX-License-Identifier: GPL-2.0-only
/*
 * A Role Based Access Control LSM
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
#include <linux/refcount.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include "rbac.h"

static int next_perm_id = 0;
struct rbac_user {
	uid_t			uid;
	struct rbac_role	*role;
	struct list_head	entry;
};

struct rbac_role {
	char			name[ROLE_NAME_LEN];
	struct rbac_permission	*perms[ROLE_MAX_PERMS];
	refcount_t		ref;
	struct list_head	entry;
};

struct rbac_permission {
	int			id;
	rbac_acc_t		acc;
	rbac_op_t		op;
	rbac_obj_t		obj;
	char			*obj_path;
	refcount_t		ref;
	struct list_head	entry;
};
static const char *acceptability_name[] = {
	[ACC_ACCEPT] = "accept",
	[ACC_DENY] = "deny",
};
static const char *operation_name[] = {
	[OP_READ] = "read",
	[OP_WRITE] = "write",
};

static struct rbac_user *rbac_get_user_by_uid(uid_t uid)
{
	struct rbac_user *ret;
	list_for_each_entry(ret, &rbac_users, entry) {
		if (ret->uid == uid)
			return ret;
	}

	return NULL;
}

static struct rbac_role *rbac_get_role_by_name(char *name)
{
	struct rbac_role *ret;
	list_for_each_entry(ret, &rbac_roles, entry) {
		if (!strcmp(ret->name, name))
			return ret;
	}

	return NULL;
}

static struct rbac_permission *rbac_get_perm_by_id(int id)
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

int rbac_check_access(uid_t uid, struct inode *inode, int mask)
{
	int ret = 0, i;
	struct rbac_user *user;
	struct rbac_role *role;
	struct rbac_permission *perm = NULL;

	/* user dose not exist */
	if ((user = rbac_get_user_by_uid(uid)) == NULL) {
		ret = 0;
		goto out;
	}

	/* user is not registered */
	if (user->role == NULL) {
		ret = 0;
		goto out;
	}
	role = user->role;

	for (i = 0; i < ROLE_MAX_PERMS; i++) {
		perm = role->perms[i];
		if (perm != NULL && perm->obj == inode) {
			if (mask & MAY_READ &&
			    perm->acc == ACC_DENY &&
			    perm->op == OP_READ) {
				ret = -EPERM;
				goto out;
			}
			
			if (mask & MAY_WRITE &&
			    perm->acc == ACC_DENY &&
			    perm->op == OP_WRITE) {
				ret = -EPERM;
				goto out;
			}
		}
	}

out:
	return ret;
}

int rbac_add_user(uid_t uid)
{
	struct rbac_user *new_user;
	int ret = 0;

	/* First check if user with name exists */
	if (rbac_get_user_by_uid(uid) != NULL) {
		ret = -EINVAL;
		goto out;
	}

	/* Second alloc memory space for the new user */
	new_user = kzalloc(sizeof(struct rbac_user), GFP_KERNEL);
	if (new_user == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* Finally initialize the new user */
	new_user->uid = uid;
	/* we do not initialize role field because we use kzalloc */
	list_add_tail(&new_user->entry, &rbac_users);

out:
	return ret;
}

int rbac_remove_user(uid_t uid)
{
	struct rbac_user *user;
	int ret = 0;

	/* First check if user with name exists */
	if ((user = rbac_get_user_by_uid(uid)) == NULL) {
		ret = -EINVAL;
		goto out;
	}

	/* Second remove the selected role from the list */
	if (user->role != NULL) {
		refcount_dec(&user->role->ref);
	}
	list_del(&user->entry);

	/* Finally free memory space of the removed role */
	kfree(user);

out:
	return ret;
}

int rbac_get_users_info(char *buf)
{
	int off = 0;
	struct rbac_user *user;

	list_for_each_entry(user, &rbac_users, entry) {
		off += sprintf(buf + off, "uid: %d", user->uid);
		if (user->role != NULL) {
			off += sprintf(buf + off, " acts as role \"%s\"", user->role->name);
		}
		off += sprintf(buf + off, "\n");
	}

	return 0;
}

int rbac_add_role(char *name)
{
	struct rbac_role *new_role;
	int ret = 0;

	/* First check if role with name exists */
	if (rbac_get_role_by_name(name) != NULL) {
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
	refcount_set(&new_role->ref, 1);
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
	if ((role = rbac_get_role_by_name(name)) == NULL) {
		ret = -EINVAL;
		goto out;
	}
	if (refcount_read(&role->ref) != 1) {
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

int rbac_get_roles_info(char *buf)
{
	int off = 0, i;
	struct rbac_role *role;

	list_for_each_entry(role, &rbac_roles, entry) {
		off += sprintf(buf + off, "%s", role->name);
		for (i = 0; i < ROLE_MAX_PERMS; i++) {
			if (role->perms[i] != NULL)
				off += sprintf(buf + off,
					       "\n\tperm[%d] id: %d", i,
					       role->perms[i]->id);
		}
		off += sprintf(buf + off, "\n");
	}

	return 0;
}

int rbac_add_permission(rbac_acc_t acc, rbac_op_t op, rbac_obj_t obj, char *obj_path)
{
	int ret = 0;
	struct rbac_permission *new_perm;

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
	new_perm->obj_path = obj_path;
	refcount_set(&new_perm->ref, 1);

	/* Finally add the new permission to the list */
	list_add_tail(&new_perm->entry, &rbac_perms);

out:
	return ret;
}

int rbac_remove_permission(int id)
{
	int ret = 0;
	struct rbac_permission *perm;

	/* find the removing permission by id */
	if ((perm = rbac_get_perm_by_id(id)) == NULL) {
		ret = -EINVAL;
		goto out;
	}
	if (refcount_read(&perm->ref) != 1) {
		ret = -EINVAL;
		goto out;
	}

	/* remove the selected permission from the list */
	list_del(&perm->entry);
	kfree(perm->obj_path);
	kfree(perm);

out:
	return ret;
}

int rbac_get_perms_info(char *buf)
{
	int off = 0;
	struct rbac_permission *perm;

	list_for_each_entry(perm, &rbac_perms, entry) {
		off += sprintf(buf + off, "[%d]: %s %s on %s\n",
			       perm->id, acceptability_name[perm->acc],
			       operation_name[perm->op], perm->obj_path);
	}

	return 0;
}

int rbac_bind_permission(int id, char *name)
{
	int ret = 0, i;
	struct rbac_permission *perm;
	struct rbac_role *role;

	if ((perm = rbac_get_perm_by_id(id)) == NULL) {
		ret = -EINVAL;
		goto out;
	}
	if ((role = rbac_get_role_by_name(name)) == NULL) {
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < ROLE_MAX_PERMS; i++) {
		if (role->perms[i] == NULL) {
			role->perms[i] = perm;
			refcount_inc(&perm->ref);
			break;
		}
	}
	if (i == ROLE_MAX_PERMS) {
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

int rbac_unbind_permission(int rid, char *name)
{
	int ret = 0;
	struct rbac_permission *perm;
	struct rbac_role *role;

	if ((role = rbac_get_role_by_name(name)) == NULL) {
		ret = -EINVAL;
		goto out;
	}
	
	perm = role->perms[rid];
	if (perm == NULL) {
		ret = -EINVAL;
		goto out;
	}
	role->perms[rid] = NULL;
	refcount_dec(&perm->ref);

out:
	return ret;
}

int rbac_register_user(uid_t uid, char *name)
{
	int ret = 0;
	struct rbac_user *user;
	struct rbac_role *role;

	if ((user = rbac_get_user_by_uid(uid)) == NULL) {
		ret = -EINVAL;
		goto out;
	}
	if ((role = rbac_get_role_by_name(name)) == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (user->role != NULL) {
		ret = -EINVAL;
		goto out;
	}

	user->role = role;
	refcount_inc(&role->ref);

out:
	return ret;
}

int rbac_unregister_user(uid_t uid)
{
	int ret = 0;
	struct rbac_user *user;
	struct rbac_role *role;

	if ((user = rbac_get_user_by_uid(uid)) == NULL) {
		ret = -EINVAL;
		goto out;
	}
	
	role = user->role;
	if (user == NULL) {
		ret = -EINVAL;
		goto out;
	}
	user->role = NULL;
	refcount_dec(&role->ref);

out:
	return ret;
}
