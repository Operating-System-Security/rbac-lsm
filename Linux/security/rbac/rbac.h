#ifndef _SECURITY_RBAC_RBAC_H
#define _SECURITY_RBAC_RBAC_H

#include <linux/list.h>
#include <linux/types.h>

#define ROLE_NAME_LEN	20
#define ROLE_MAX_PERMS	20

typedef enum {
	ACC_ACCEPT,
	ACC_DENY,
} acceptablity_t;

typedef enum {
	OP_READ,
	OP_WRITE,
} operation_t;

static const char *acceptability_name[] = {
	[ACC_ACCEPT] = "accept",
	[ACC_DENY] = "deny",
};

static const char *operation_name[] = {
	[OP_READ] = "read",
	[OP_WRITE] = "write",
};

typedef char* object_t;

struct rbac_user {
	int			uid;
	struct rbac_role	*role;
};

struct rbac_role {
	char			name[ROLE_NAME_LEN];
	struct list_head	entry;
	struct rbac_permission	*perms[ROLE_MAX_PERMS];
};

struct rbac_permission {
	int			id;
	acceptablity_t		acc;
	operation_t		op;
	object_t		obj;
	struct list_head	entry;
};

#endif
