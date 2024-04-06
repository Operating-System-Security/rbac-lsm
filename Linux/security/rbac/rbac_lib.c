// SPDX-License-Identifier: GPL-2.0-only
/*
 * A Role Based Access Control LSM
 *
 * Copyright 2024 Miao Hao <haomiao19@mails.ucas.ac.cn>
 */

#include <linux/string.h>

/* NOTE: the length of char *tokens[] must be larger than len */
int rbac_get_nargs(char **args, int len, char **tokens)
{
	int i = 0;
	const char delim[] = " \n";

	while (i < len && (tokens[i] = strsep(args, delim)) != NULL) {
		i++;
	}

	return i;
}
