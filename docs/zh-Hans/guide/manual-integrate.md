# 手动集成参考 {#hooks}

## 手动挂钩 {#scope-minimized-hooks}

::: danger Notice：
ReSukiSU 将会检查此处每一条 hook，如果缺少，将会**导致编译失败**
:::

:::info 提示
这一部分的钩子，改编于 [`backslashxx/KernelSU #5`](https://github.com/backslashxx/KernelSU/issues/5)
:::

### stat hooks <Badge type="danger" text="必加"/> {#stat-hooks}

::: code-group
```diff[stat.c]
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -353,6 +353,10 @@ SYSCALL_DEFINE2(newlstat, const char __user *, filename,
 	return cp_new_stat(&stat, statbuf);
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+__attribute__((hot)) 
+extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
+				int *flags);
+
+extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
+#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
+extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr); // optional
+#endif
+#endif
+
 #if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)
 SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
 		struct stat __user *, statbuf, int, flag)
@@ -360,6 +364,9 @@ SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
 	struct kstat stat;
 	int error;
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_stat(&dfd, &filename, &flag);
+#endif
 	error = vfs_fstatat(dfd, filename, &stat, flag);
 	if (error)
 		return error;
@@ -504,6 +511,9 @@ SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
 	struct kstat stat;
 	int error;
 
+#ifdef CONFIG_KSU_MANUAL_HOOK // 32-bit su
+	ksu_handle_stat(&dfd, &filename, &flag); 
+#endif
 	error = vfs_fstatat(dfd, filename, &stat, flag);
 	if (error)
 		return error;

@@ -364,X +364,XX @@  
SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_new_stat(&stat, statbuf);

+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_newfstat_ret(&fd, &statbuf);
+#endif
	return error;

 
@@ -490,X +497,X @@
SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_new_stat64(&stat, statbuf);

+#ifdef CONFIG_KSU_MANUAL_HOOK // for 32-bit
+	ksu_handle_fstat64_ret(&fd, &statbuf);
+#endif
	return error;
}
```
:::

在 `fs/stat.c` 中，你需要找到 `newfstatat` 和 `fstatat64`（如果支持 32-bit su）并 hook 它们。你还需要 hook `newfstat` 和 `fstat64`（如果支持 32-bit su）以获取返回值。

### execve hook <Badge type="danger" text="必加"/> {#execve-hooks}

对于此 hook，不同版本内核不一致，此处单独说明


::: code-group
```diff[3.14+]
--- a/fs/exec.c
+++ b/fs/exec.c
@@ -1886,12 +1886,26 @@ static int do_execveat_common(int fd, struct filename *filename,
 	return retval;
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+__attribute__((hot))
+extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
+				void *argv, void *envp, int *flags);
+#endif
+
 int do_execve(struct filename *filename,
 	const char __user *const __user *__argv,
 	const char __user *const __user *__envp)
 {
 	struct user_arg_ptr argv = { .ptr.native = __argv };
 	struct user_arg_ptr envp = { .ptr.native = __envp };
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
+#endif
 	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
 }
 
@@ -1919,6 +1933,10 @@ static int compat_do_execve(struct filename *filename,
 		.is_compat = true,
 		.ptr.compat = __envp,
 	};
+#ifdef CONFIG_KSU_MANUAL_HOOK // 32-bit ksud and 32-on-64 support
+	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
+#endif
 	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
 }
```
```diff[3.14-]
--- a/fs/exec.c
+++ b/fs/exec.c
@@ -1649,6 +1649,12 @@ static int do_execve_common(const char *filename,
 	return retval;
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+__attribute__((hot))
+extern int ksu_handle_execve(int *fd, const char *filename,
+				void *argv, void *envp, int *flags);
+#endif
+
 int do_execve(const char *filename,
 	const char __user *const __user *__argv,
 	const char __user *const __user *__envp,
@@ -1656,6 +1662,9 @@ int do_execve(const char *filename,
 {
 	struct user_arg_ptr argv = { .ptr.native = __argv };
 	struct user_arg_ptr envp = { .ptr.native = __envp };
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_execve((int *)AT_FDCWD, filename, &argv, &envp, 0);
+#endif
 	return do_execve_common(filename, argv, envp, regs);
 }
 
@@ -1673,6 +1682,9 @@ int compat_do_execve(char *filename,
 		.is_compat = true,
 		.ptr.compat = __envp,
 	};
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_execve((int *)AT_FDCWD, filename, &argv, &envp, 0);
+#endif
 	return do_execve_common(filename, argv, envp, regs);
 }
 #endif
```
:::

在这部分中 修改 `fs/exec.c` 中的 `do_execve`。注意对于 32-bit su 和 32-on-64，你还需要在同一文件中 hook `compat_do_execve`。

对于 3.14- 内核，你需要使用 `ksu_handle_execve`，而不是 `ksu_handle_execveat`，且其传入参数也略有不同于 3.14+ 内核，需要根据实际情况进行调整。

### faccessat hook <Badge type="danger" text="必加"/> {#faccessat-hook}
对于此 hook，不同版本内核不一致，此处单独说明

::: code-group

```diff[4.19+]
--- a/fs/open.c
+++ b/fs/open.c
@@ -450,8 +450,16 @@ long do_faccessat(int dfd, const char __user *filename, int mode)
 	return res;
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+__attribute__((hot)) 
+extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
+				int *mode, int *flags);
+#endif
+
 SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 {
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+#endif
 	return do_faccessat(dfd, filename, mode);
 }
```
```diff[4.19-]
--- a/fs/open.c
+++ b/fs/open.c
@@ -354,6 +354,11 @@ SYSCALL_DEFINE4(fallocate, int, fd, int, mode, loff_t, offset, loff_t, len)
 	return error;
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+__attribute__((hot)) 
+extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
+				int *mode, int *flags);
+#endif
+
 /*
  * access() needs to use the real uid/gid, not the effective uid/gid.
  * We do this by temporarily clearing all FS-related capabilities and
@@ -369,6 +374,10 @@ SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 	int res;
 	unsigned int lookup_flags = LOOKUP_FOLLOW;
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+#endif
+
 	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
 		return -EINVAL;
```
:::

在这部分中，你需要在 `fs/open.c` 中找到 `faccessat` 的 SYSCALL 并 hook 它。

### sys_reboot hook <Badge type="danger" text="必加"/> {#sys-reboot-hook}
对于此 hook，不同版本内核不一致，此处单独说明

::: code-group

```diff[3.11+]
--- a/kernel/reboot.c
+++ b/kernel/reboot.c
@@ -277,6 +277,11 @@ static DEFINE_MUTEX(reboot_mutex);
  *
  * reboot doesn't sync: do that yourself before calling this.
  */
+
+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
+#endif
+
 SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
 		void __user *, arg)
 {
@@ -284,6 +289,9 @@ SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
 	char buffer[256];
 	int ret = 0;
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
+#endif
 	/* We only trust the superuser with rebooting the system. */
 	if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
 		return -EPERM;
```

```diff[3.11-]
diff --git a/kernel/sys.c b/kernel/sys.c
index a3bef5bd..08d196f5 100644
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -455,6 +455,10 @@ EXPORT_SYMBOL_GPL(kernel_power_off);

 static DEFINE_MUTEX(reboot_mutex);

+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
+#endif
+
 /*
  * Reboot system call: for obvious reasons only root may call it,
  * and even root needs to set up some magic numbers in the registers
@@ -470,6 +474,10 @@ SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
        char buffer[256];
        int ret = 0;

+#ifdef CONFIG_KSU_MANUAL_HOOK
+       ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
+#endif
+
        /* We only trust the superuser with rebooting the system. */
        if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
                return -EPERM;
```
:::

在这部分中，你需要在内核源码中找到 `reboot`的 SYSCALL 并 hook 它。注意对于 3.11- 内核，你需要在 `kernel/sys.c` 中 hook `reboot`，而不是在 `kernel/reboot.c` 中。

### input hooks <Badge type="tip" text="按需必加"/> {#input-hooks}
:::warning 一般无需此手动 hook
对于 input handler 未损坏的内核，只需保证 `CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK` 处于启用状态，此 hook 即可通过 input_hanlder 自动应用
:::

::: code-group
```diff[input.c]
--- a/drivers/input/input.c
+++ b/drivers/input/input.c
@@ -436,11 +436,22 @@ static void input_handle_event(struct input_dev *dev,
  * to 'seed' initial state of a switch or initial position of absolute
  * axis, etc.
  */
+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern bool ksu_input_hook __read_mostly;
+extern __attribute__((cold)) int ksu_handle_input_handle_event(
+			unsigned int *type, unsigned int *code, int *value);
+#endif
+
 void input_event(struct input_dev *dev,
 		 unsigned int type, unsigned int code, int value)
 {
 	unsigned long flags;
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	if (unlikely(ksu_input_hook))
+		ksu_handle_input_handle_event(&type, &code, &value);
+#endif
+
 	if (is_event_supported(type, dev->evbit, EV_MAX)) {
 
 		spin_lock_irqsave(&dev->event_lock, flags);
```
:::

在这部分中，你需要在 `drivers/input/input.c` 中找到 `input_event` 并 hook 它。

### setuid hooks <Badge type="warning" text="6.8+ 必加"/> <Badge type="warning" text="4.2- 必加"/> {#setuid-hooks}
:::warning 大部分版本不需要此手动 hook
对于 4.2~6.8(不包括6.8) 的内核，只需保证 `CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK` 处于启用状态，此 hook 即可通过 LSM 自动应用
:::

::: code-group
```diff[4.17+]
diff --git a/kernel/sys.c b/kernel/sys.c
index 4a87dc5fa..aac25df8c 100644
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -679,6 +679,10 @@ SYSCALL_DEFINE1(setuid, uid_t, uid)
 }


+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);
+#endif
+
 /*
  * This function implements a generic ability to update ruid, euid,
  * and suid.  This allows you to implement the 4.4 compatible seteuid().
@@ -692,6 +696,10 @@ long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
        kuid_t kruid, keuid, ksuid;
        bool ruid_new, euid_new, suid_new;

+#ifdef CONFIG_KSU_MANUAL_HOOK
+       (void)ksu_handle_setresuid(ruid, euid, suid);
+#endif
+
        kruid = make_kuid(ns, ruid);
        keuid = make_kuid(ns, euid);
        ksuid = make_kuid(ns, suid);
```
```diff[4.17-]
diff --git a/kernel/sys.c b/kernel/sys.c
index a3bef5bd..0b116d7c 100644
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -835,6 +843,9 @@ error:
        return retval;
 }

+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);
+#endif

 /*
  * This function implements a generic ability to update ruid, euid,
@@ -848,6 +859,10 @@ SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
        int retval;
        kuid_t kruid, keuid, ksuid;

+#ifdef CONFIG_KSU_MANUAL_HOOK
+       (void)ksu_handle_setresuid(ruid, euid, suid);
+#endif
+
        kruid = make_kuid(ns, ruid);
        keuid = make_kuid(ns, euid);
        ksuid = make_kuid(ns, suid);
```
:::

在这部分中，你需要在内核源码中找到 `__sys_setresuid`并 hook 它。注意对于 4.17- 内核，你需要 hook `setresuid` 而不是 `__sys_setresuid`。

### sys_read hook <Badge type="warning" text="6.8+ 必加"/> <Badge type="warning" text="4.2- 必加"/> {#sys-read-hook}
:::warning 大部分版本不需要此手动 hook
对于 4.2~6.8(不包括6.8) 的内核，只需保证 `CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK` 处于启用状态，此 hook 即可通过 LSM 自动应用
:::

::: code-group
```diff[4.19+]
--- a/fs/read_write.c
+++ b/fs/read_write.c
@@ -586,8 +586,18 @@ ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
 	return ret;
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern bool ksu_init_rc_hook __read_mostly;
+extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,
+				char __user **buf_ptr, size_t *count_ptr);
+#endif
+
 SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 {
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	if (unlikely(ksu_init_rc_hook)) 
+		ksu_handle_sys_read(fd, &buf, &count);
+#endif
 	return ksys_read(fd, buf, count);
 }
```
```diff[4.19-]
--- a/fs/read_write.c
+++ b/fs/read_write.c
@@ -568,11 +568,21 @@ static inline void file_pos_write(struct file *file, loff_t pos)
 		file->f_pos = pos;
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern bool ksu_init_rc_hook __read_mostly;
+extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,
+				char __user **buf_ptr, size_t *count_ptr);
+#endif
+
 SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 {
 	struct fd f = fdget_pos(fd);
 	ssize_t ret = -EBADF;
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	if (unlikely(ksu_init_rc_hook)) 
+		ksu_handle_sys_read(fd, &buf, &count);
+#endif
 	if (f.file) {
 		loff_t pos = file_pos_read(f.file);
 		ret = vfs_read(f.file, buf, count, &pos);
```
:::

在这部分中，你需要在 `fs/read_write.c` 中找到 `read` 的 `SYSCALL` 并 hook 它。

### rename hook <Badge type="warning" text="4.2- 必加"/> {#rename-hook}

::: warning
大部分版本不需要此手动 hook,该hook仅适用于 4.2- 内核
:::

::: code-group
```diff[security.c]
diff --git a/security/security.c b/security/security.c
index bb41f113d3d92..584c30fd811d3 100644
--- a/security/security.c
+++ b/security/security.c
@@ -526,12 +526,18 @@ int security_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
 	return security_ops->inode_mknod(dir, dentry, mode, dev);
 }
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern void ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry);
+#endif
+
 int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
 			   struct inode *new_dir, struct dentry *new_dentry)
 {
         if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
             (new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
 		return 0;
+
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	ksu_handle_rename(old_dentry, new_dentry);
+#endif
 	return security_ops->inode_rename(old_dir, old_dentry,
 					   new_dir, new_dentry);
 }
```
:::

在这部分中，你需要在 `security/security.c` 中找到 `security_inode_rename` 并 hook 它。

### ksu key permission hook {#key-permission-hook}

::: warning
大部分版本不需要此手动 hook,该hook仅适用于 4.2- 内核
:::

::: code-group
```diff[security.c]
diff --git a/security/security.c b/security/security.c
index 584c30fd..57670e6a 100644
--- a/security/security.c
+++ b/security/security.c
@@ -1336,9 +1336,16 @@ void security_key_free(struct key *key)
security_ops->key_free(key);
}

+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern int ksu_key_permission(key_ref_t key_ref, const struct cred *cred, unsigned perm);
+#endif
+
int security_key_permission(key_ref_t key_ref,
const struct cred *cred, key_perm_t perm)
{
+#ifdef CONFIG_KSU_MANUAL_HOOK
+ ksu_key_permission(key_ref, cred, perm);
+#endif
return security_ops->key_permission(key_ref, cred, perm);
}
```
:::

在这部分中，你需要在 `security/security.c` 中找到 `security_key_permission` 并 hook 它。

## policy_rwlock export <Badge type="info" text="4.14- 可选"/> {#policy-rwlock-export}

::: info Notes
这是一个可选选项,但不修改这一部分可能会导致某些设备上内存管理方面的安全性问题
:::

```diff
diff --git a/security/selinux/ss/services.c b/security/selinux/ss/services.c
index b818410d2418..ea2f3022744f 100644
--- a/security/selinux/ss/services.c
+++ b/security/selinux/ss/services.c
@@ -76,7 +76,7 @@ int selinux_policycap_netpeer;
 int selinux_policycap_openperm;
 int selinux_policycap_alwaysnetwork;
 
-static DEFINE_RWLOCK(policy_rwlock);
+DEFINE_RWLOCK(policy_rwlock);
 
 static struct sidtab sidtab;
 struct policydb policydb;

```

在这部分中,修改相对较简单，仅需在 `security/selinux/ss/services.c` 中找到 `policy_rwlock` 的定义，并将其前面的 `static` 关键字去掉即可。

## path_umount <Badge type="info" text="可选"/> {#how-to-backport-path-umount}

::: info Notes
这是一个可选选项，你可以不移植这一部分
:::

你可以通过从 K5.9 向旧版本移植 `path_umount`，在 GKI 之前的内核上获得卸载模块的功能。你可以通过以下补丁作为参考:

```diff
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -1739,6 +1739,39 @@ static inline bool may_mandlock(void)
 }
 #endif

+static int can_umount(const struct path *path, int flags)
+{
+	struct mount *mnt = real_mount(path->mnt);
+
+	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
+		return -EINVAL;
+	if (!may_mount())
+		return -EPERM;
+	if (path->dentry != path->mnt->mnt_root)
+		return -EINVAL;
+	if (!check_mnt(mnt))
+		return -EINVAL;
+	if (mnt->mnt.mnt_flags & MNT_LOCKED) /* Check optimistically */
+		return -EINVAL;
+	if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
+		return -EPERM;
+	return 0;
+}
+
+int path_umount(struct path *path, int flags)
+{
+	struct mount *mnt = real_mount(path->mnt);
+	int ret;
+
+	ret = can_umount(path, flags);
+	if (!ret)
+		ret = do_umount(mnt, flags);
+
+	/* we mustn't call path_put() as that would clear mnt_expiry_mark */
+	dput(path->dentry);
+	mntput_no_expire(mnt);
+	return ret;
+}
 /*
  * Now umount can handle mount points as well as block devices.
  * This is important for filesystems which use unnamed block devices.
```
