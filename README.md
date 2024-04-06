# rbac-lsm: 角色访问控制内核安全模块

## 策略

在 RBAC 中，用户（user）与角色（role）、角色与权限（permission）均可以是多对多关系，而本实验仅关注实现原理，因此用户与角色为一对一关系。用户、角色与权限的关系可以表示为：

用户 $\to$ 角色 $\rightrightarrows$ 权限

进一步可以将权限分解：权限 $=$ acceptability $+$  operation $+$ object

因此可以用多重正交元组表示“一个用户具有某个权限”：$U\times R\times A \times Op\times O$，其中 $U$ 表示用户（User），$R$ 表示角色（Role），$A$ 表示接受性（Acceptability），$Op$ 表示操作（Operation），$O$ 表示客体（Object）。

数据库中存储若干这样的四元组，当 $U_i$ 通过 $Op_j$ 访问 $O_k$ 时，检查数据库中是否存在 $(U_i, R_l, A_m, Op_j, O_k)$，若存在且 $A_m$ 为允许，**或四元组不存在**，则允许访问；若存在且 $A_m$ 为拒绝，则拒绝访问。

## 机制

$U$ 可以用内核中的 `uid` 标记，$R$ 自定义实现，$A$、$Op$ 采用枚举自定义，$O$ 使用 `inode` 指针标记。

在功能上将其分为 3 个层次：
- db 层：负责底层内核数据对象的管理
- fs 层：负责维护与用户交互的文件接口
- lsm：负责实现 RBAC 访问策略

在一次访问请求中，可能会进行多个操作，只要其中有一个拒绝了，就拒绝这次访问，否则接受访问。

## 实现

### db 层

db 层负责实现内核数据对象的管理，向上提供接口供 fs 层和 lsm 进行使用。rbac-lsm 实现的内核数据对象包括：

- `rbac_user`：用户管理，每个用户可以关联到一个角色

  ```c
  struct rbac_user {
  	uid_t			uid;
  	struct rbac_role	*role;
  	struct list_head	entry;
  };
  ```
- `rbac_role`：角色管理，每个角色可以关联至多 20 个权限

  ```c
  struct rbac_role {
  	char			name[ROLE_NAME_LEN];
  	struct rbac_permission	*perms[ROLE_MAX_PERMS];
  	refcount_t		ref;
  	struct list_head	entry;
  };
  ```
- `rbac_permission`：权限管理，每个权限包含接受性、操作和客体三个关键域

  ```c
  struct rbac_permission {
  	int			id;
  	rbac_acc_t		acc;
  	rbac_op_t		op;
  	rbac_obj_t		obj;
  	char			*obj_path;
  	refcount_t		ref;
  	struct list_head	entry;
  };
  ```

所有的 `rbac_user`、`rbac_role` 和 `rbac_perm` 对象通过 3 个全局的链表进行维护。对于 fs 层，db 层实现了对应的操作，可以在全局链表中创建/删除对应的内核对象；对于 lsm，db 负责根据用户某次访问时所包含的操作和客体，查询链表（数据库），判断接受/拒绝该次访问。

## fs 层

fs 层基于 securityfs 机制，在 `/sys/kernel/security/rbac` 下建立了一些列虚拟文件，实现了用户与 lsm 的交互功能。

伪文件系统下包含的文件：

|文件名|属性|说明|
|:---:|:---:|:---:|
|`enable`|读写|获取/改变 rbac-lsm 使能|
|`user`|只读|获取已添加的用户信息|
|`role`|只读|获取已添加的角色信息|
|`perm`|只读|获取已添加的权限信息|
|`ctrl`|只写|添加、删除内核数据对象，改变其间的关系|

### `enable`

可以通过向 `enable` 文件中写 `0` 或 `1` 改变 rbac-lsm 的使能状态，其中 `0` 表示关闭；`1` 表示开启。

```sh
# echo 0 > enable
# cat enable
rbac: disabled
# echo 1 > enable
# cat enable
rbac: enabled
```

### `user`

读 `user` 以获取目前 rbac-lsm 已知的用户信息。

```sh
# cat user
uid: 0 acts as role "admin"
uid: 1000
```

目前 rbac-lsm 已经添加了 2 个用户，其中 `uid` 为 `0` 的用户已经绑定到了名为 `admin` 的角色上； `uid` 为 `1000` 的用户未绑定到任何角色。

### `role`

读 `role` 以获取目前 rbac-lsm 中已添加的角色信息。

```sh
# cat role
admin
	perm[0]
guest
```

目前 rbac-lsm 已经添加了 2 个角色，其中名为 `admin` 的角色已经绑定了一个 `id` 为 `0` 的权限；名为 `guest` 的角色未绑定任何权限。

### `perm`

读 `perm` 以获取目前 rbac-lsm 中已添加的权限。

```sh
# cat perm
[0]: deny write on /init
[1]: accept read on /
[2]: deny read on /init
[3]: deny write on /
```

目前 rbac-lsm 已经添加了 4 条权限，其中 `id` 为 `0` 的权限表示不允许写 `/init`；`id` 为 `1` 的权限表示允许读 `/`；`id` 为 `2` 的权限表示不允许读 `/init`；`id` 为 `3` 的权限表示不允许写 `/`。

## `ctrl`

向 `ctrl` 写命令以实现对内核数据对象的修改，支持的命令包括：

- add user <u>UID</u>：添加用户，其 `uid` 为 <u>UID</u>
- remove user <u>UID</u>：删除用户，其 `uid` 为 <u>UID</u>
- add role <u>NAME</u>：添加名字为 <u>NAME</u> 的角色
- remove role <u>NAME</u>：删除名字为 <u>NAME</u> 的角色
- add perm <u>ACC</u> <u>OP</u> <u>OBJ</u>：添加接受性为 <u>ACC</u>，操作为 <u>OP</u>，客体为 <u>OBJ</u> 的权限
- remove perm <u>ID</u>：删除 id 为 <u>ID</u> 的权限
- register <u>UID</u> <u>NAME</u>：将 `uid` 为 <u>UID</u> 的 user 和名字为 <u>NAME</u> 的 role 绑定
- unregister <u>UID</u> <u>NAME</u>：解除 `uid` 为 <u>UID</u> 的 user 和名字为 <u>NAME</u> 的 role 绑定
- bind <u>ID</u> <u>NAME</u>：将 id 为 <u>ID</u> 的权限绑定到名字为 <u>NAME</u> 的 role 上
- unbind <u>RID</u> <u>NAME</u>：将 id 为 <u>ID</u> 的权限到名字为 <u>NAME</u> 的 role 的绑定解除

目前支持的参数可选值为：

|名称|可选值|
|:---:|:---:|
|UID|任意非负整数|
|NAME|任意字符串|
|ACC|`a` 表示接受；`d` 表示拒绝|
|OP|`r` 表示读；`w` 表示写|
|OBJ|任意绝对路径|
|RID|将权限绑定到角色后，权限在角色上的 id|

## lsm

lsm 通过将权限检查钩子挂在 `inode_permission` 上以接受/拒绝某次访问：

```c
static struct security_hook_list rbac_hooks[] = {
	LSM_HOOK_INIT(inode_permission, rbac_inode_permission),
};
```

db 层实现了接口 `int rbac_check_access(uid_t uid, struct inode *inode, int mask)` 根据 `uid`（用户），`inode`（客体）和 `mask`（操作），进行权限检查，过程为：

- 通过 `uid` 查询用户信息，进一步获取当前用户的角色 `role`
- 遍历 `role` 中包含的每一条权限，根据 `inode` 和 `mask` 找到客体和操作与本次访问相同的权限
- 根据权限中的接受性接受/拒绝本次访问
