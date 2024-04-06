#ifndef _SECURITY_RBAC_RBAC_H
#define _SECURITY_RBAC_RBAC_H

#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/types.h>

#define RBAC_NAME "rbac"
#define ROLE_NAME_LEN	20
#define ROLE_MAX_PERMS	20

typedef enum {
	ACC_ACCEPT,
	ACC_DENY,
} rbac_acc_t;

typedef enum {
	OP_READ,
	OP_WRITE,
} rbac_op_t;

typedef char* rbac_obj_t;

struct rbac_user {
	int			uid;
	struct rbac_role	*role;
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
	refcount_t		ref;
	struct list_head	entry;
};

extern struct list_head rbac_roles;
extern struct list_head rbac_perms;
extern int rbac_enable;

extern int rbac_add_role(char *name);
extern int rbac_remove_role(char *name);
extern int rbac_add_permission(rbac_acc_t acc, rbac_op_t op, rbac_obj_t obj);
extern int rbac_remove_permission(int id);

extern int rbac_get_nargs(char **args, int len, char **tokens);

#endif
