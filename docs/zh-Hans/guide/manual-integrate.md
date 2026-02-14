# 手动集成参考 {#hooks}

## 手动挂钩 {#scope-minimized-hooks}

::: danger Notice：
ReSukiSU 将会检查此处每一条 hook，如果缺少，将会**导致编译失败**
:::

:::info 提示
这一部分的钩子，改编于 [`backslashxx/KernelSU #5`](https://github.com/backslashxx/KernelSU/issues/5)
:::

### 通用钩子 <Badge type="danger" text="必加"/> {#generic-hooks}
::: code-group

```diff[exec.c]
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
```diff[reboot.c]
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
:::

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

### input hooks <Badge type="tip" text="按需必加"/> {#input-hooks}
:::warning 一般无需此手动 hook
对于input handler 未损坏的内核，只需保证 `CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK` 处于启用状态，此 hook 即可通过 input_hanlder 自动应用
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

### setuid hooks <Badge type="warning" text="6.8+ 必加"/> {#setuid-hooks}
:::warning 大部分版本不需要此手动 hook
对于 6.8- 内核，只需保证 `CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK` 处于启用状态，此 hook 即可通过 LSM 自动应用
:::

::: code-group
```diff[sys.c]
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
:::

### sys_read hook <Badge type="warning" text="6.8+ 必加"/> {#sys-read-hook}
:::warning 大部分版本不需要此手动 hook
对于 6.8- 内核，只需保证 `CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK` 处于启用状态，此 hook 即可通过 LSM 自动应用
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
+extern bool ksu_sys_read_hook __read_mostly;
+extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,
+				char __user **buf_ptr, size_t *count_ptr);
+#endif
+
 SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 {
 	struct fd f = fdget_pos(fd);
 	ssize_t ret = -EBADF;
 
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	if (unlikely(ksu_sys_read_hook)) 
+		ksu_handle_sys_read(fd, &buf, &count);
+#endif
 	if (f.file) {
 		loff_t pos = file_pos_read(f.file);
 		ret = vfs_read(f.file, buf, count, &pos);
```
:::
### selinux hook <Badge type="warning" text="4.9- 必加"/> {#selinux-hook}
:::warning 大部分版本不需要此手动 hook
此 hook 只适用于 4.9- 内核，防止出现 无法获取 root
:::
::: code-group
```diff[hooks.c]
--- a/security/selinux/hooks.c
+++ b/security/selinux/hooks.c
+#ifdef CONFIG_KSU_MANUAL_HOOK
+extern bool is_ksu_transition(const struct task_security_struct *old_tsec, 
+				const struct task_security_struct *new_tsec);
+#endif

static int check_nnp_nosuid(const struct linux_binprm *bprm,
			    const struct task_security_struct *old_tsec,
			    const struct task_security_struct *new_tsec)
{
	int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);
	int nosuid = !mnt_may_suid(bprm->file->f_path.mnt);
	int rc;

	if (!nnp && !nosuid)
		return 0; /* neither NNP nor nosuid */

	if (new_tsec->sid == old_tsec->sid)
		return 0; /* No change in credentials */
+
+#ifdef CONFIG_KSU_MANUAL_HOOK
+	if (is_ksu_transition(old_tsec, new_tsec))
+		return 0;
+#endif

	/*
	 * The only transitions we permit under NNP or nosuid
	 * are transitions to bounded SIDs, i.e. SIDs that are
```
:::

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
