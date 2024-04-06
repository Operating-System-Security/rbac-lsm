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

extern struct list_head rbac_users;
extern struct list_head rbac_roles;
extern struct list_head rbac_perms;
extern int rbac_enable;

extern int rbac_add_user(uid_t uid);
extern int rbac_remove_user(uid_t uid);
extern int rbac_get_users_info(char *buf);
extern int rbac_add_role(char *name);
extern int rbac_remove_role(char *name);
extern int rbac_get_roles_info(char *buf);
extern int rbac_add_permission(rbac_acc_t acc, rbac_op_t op, rbac_obj_t obj);
extern int rbac_remove_permission(int id);
extern int rbac_get_perms_info(char *buf);

extern int rbac_bind_permission(int id, char *name);
extern int rbac_unbind_permission(int rid, char *name);
extern int rbac_register_user(uid_t uid, char *name);
extern int rbac_unregister_user(uid_t uid);

extern int rbac_get_nargs(char **args, int len, char **tokens);

#endif
