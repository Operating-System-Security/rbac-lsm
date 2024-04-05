// SPDX-License-Identifier: GPL-2.0-only
/*
 * A Role Based Accessment Control LSM
 *
 * Copyright 2024 Miao Hao <haomiao19@mails.ucas.ac.cn>
 */
#include <asm-generic/errno-base.h>
#include <linux/lsm_hooks.h>
#include <linux/printk.h>
#include <linux/security.h>
#include "rbac.h"

int rbac_enable = IS_ENABLED(CONFIG_SECURITY_RBAC);

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
