# Manual hooks reference {#hooks}

::: danger Notice：
ReSukiSU will check everythings of these hooks when building,if missing one of them,it will fail.
:::

## 最小化钩子 {#scope-minimized-hooks}

:::info Note
这一部分的钩子，请查看 [`backslashxx/KernelSU #5`](https://github.com/backslashxx/KernelSU/issues/5)

这里不作重复赘述
:::

## KernelSU 官方 manual hook {#manual-hooks}

::: tip Note
This part picked from [KernelSU's document](https://kernelsu.org),and added hooks that was needed in the situations.
:::

Below are some patches for reference：

::: code-group

```diff[exec.c]
diff --git a/fs/exec.c b/fs/exec.c
index ac59664eaecf..bdd585e1d2cc 100644
--- a/fs/exec.c
+++ b/fs/exec.c
@@ -1890,11 +1890,14 @@ static int __do_execve_file(int fd, struct filename *filename,
 	return retval;
 }

+#ifdef CONFIG_KSU
+extern bool ksu_execveat_hook __read_mostly;
+extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
+			void *envp, int *flags);
+extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
+				 void *argv, void *envp, int *flags);
+#endif
 static int do_execveat_common(int fd, struct filename *filename,
 			      struct user_arg_ptr argv,
 			      struct user_arg_ptr envp,
 			      int flags)
 {
+   #ifdef CONFIG_KSU
+	if (unlikely(ksu_execveat_hook))
+		ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
+	else
+		ksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);
+   #endif
 	return __do_execve_file(fd, filename, argv, envp, flags, NULL);
 }
```
```diff[open.c]
diff --git a/fs/open.c b/fs/open.c
index 05036d819197..965b84d486b8 100644
--- a/fs/open.c
+++ b/fs/open.c
@@ -348,6 +348,8 @@ SYSCALL_DEFINE4(fallocate, int, fd, int, mode, loff_t, offset, loff_t, len)
 	return ksys_fallocate(fd, mode, offset, len);
 }

+#ifdef CONFIG_KSU
+extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
+			 int *flags);
+#endif
 /*
  * access() needs to use the real uid/gid, not the effective uid/gid.
  * We do this by temporarily clearing all FS-related capabilities and
@@ -355,6 +357,7 @@ SYSCALL_DEFINE4(fallocate, int, fd, int, mode, loff_t, offset, loff_t, len)
  */
 long do_faccessat(int dfd, const char __user *filename, int mode)
 {
 	const struct cred *old_cred;
 	struct cred *override_cred;
 	struct path path;
 	struct inode *inode;
 	struct vfsmount *mnt;
 	int res;
 	unsigned int lookup_flags = LOOKUP_FOLLOW;
+   #ifdef CONFIG_KSU
+	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+   #endif
 
 	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
 		return -EINVAL;
```
```diff[read_write.c]
diff --git a/fs/read_write.c b/fs/read_write.c
index 650fc7e0f3a6..55be193913b6 100644
--- a/fs/read_write.c
+++ b/fs/read_write.c
@@ -434,10 +434,14 @@ ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
 }
 EXPORT_SYMBOL(kernel_read);

+#ifdef CONFIG_KSU
+extern bool ksu_vfs_read_hook __read_mostly;
+extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
+			size_t *count_ptr, loff_t **pos);
+#endif
 ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
 {
 	ssize_t ret;
+   #ifdef CONFIG_KSU 
+	if (unlikely(ksu_vfs_read_hook))
+		ksu_handle_vfs_read(&file, &buf, &count, &pos);
+   #endif
+
 	if (!(file->f_mode & FMODE_READ))
 		return -EBADF;
 	if (!(file->f_mode & FMODE_CAN_READ))
```
```diff[stat.c]
diff --git a/fs/stat.c b/fs/stat.c
index 376543199b5a..82adcef03ecc 100644
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -148,6 +148,8 @@ int vfs_statx_fd(unsigned int fd, struct kstat *stat,
 }
 EXPORT_SYMBOL(vfs_statx_fd);

+#ifdef CONFIG_KSU
+extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
+#endif
+
 /**
  * vfs_statx - Get basic and extra attributes by filename
  * @dfd: A file descriptor representing the base dir for a relative filename
@@ -170,6 +172,7 @@ int vfs_statx(int dfd, const char __user *filename, int flags,
 	int error = -EINVAL;
 	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;

+   #ifdef CONFIG_KSU
+	ksu_handle_stat(&dfd, &filename, &flags);
+   #endif
 	if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
 		       AT_EMPTY_PATH | KSTAT_QUERY_FLAGS)) != 0)
 		return -EINVAL;
```
```diff[reboot.c]
diff --git a/kernel/reboot.c b/kernel/reboot.c
index 344ceaf5e..2b2a35f71 100644
--- a/kernel/reboot.c
+++ b/kernel/reboot.c
@@ -693,6 +693,10 @@ EXPORT_SYMBOL_GPL(kernel_power_off);
 
 DEFINE_MUTEX(system_transition_mutex);
 
+#ifdef CONFIG_KSU
+extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
+#endif
+
 /*
  * Reboot system call: for obvious reasons only root may call it,
  * and even root needs to set up some magic numbers in the registers
@@ -708,6 +712,10 @@ SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
 	char buffer[256];
 	int ret = 0;
 
+#ifdef CONFIG_KSU
+	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
+#endif
+
 	/* We only trust the superuser with rebooting the system. */
 	if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
 		return -EPERM;
```
:::

主要是要改五个地方：

1. `do_faccessat`, usually in `fs/open.c`
2. `do_execveat_common`, usually in `fs/exec.c`
3. `vfs_read`, usually in `fs/read_write.c`
4. `vfs_statx`, usually in `fs/stat.c`
5. `reboot`, usually in `kernel/reboot.c`

If your kernel doesn't have the `vfs_statx` function or kernel version is >= 6.1, use `vfs_fstatat` instead:
```diff
diff --git a/fs/stat.c b/fs/stat.c
index 068fdbcc9e26..5348b7bb9db2 100644
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -87,6 +87,8 @@ int vfs_fstat(unsigned int fd, struct kstat *stat)
 }
 EXPORT_SYMBOL(vfs_fstat);
 
+#ifdef CONFIG_KSU 
+extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
+#endif
+
 int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat,
 		int flag)
 {
@@ -94,6 +96,8 @@ int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat,
 	int error = -EINVAL;
 	unsigned int lookup_flags = 0;
+   #ifdef CONFIG_KSU 
+	ksu_handle_stat(&dfd, &filename, &flag);
+   #endif
+
 	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
 		      AT_EMPTY_PATH)) != 0)
 		goto out;
```

For kernels eariler than 4.17, if you cannot find `do_faccessat`, just go to the definition of the `faccessat` syscall and place the call there:

```diff
diff --git a/fs/open.c b/fs/open.c
index 2ff887661237..e758d7db7663 100644
--- a/fs/open.c
+++ b/fs/open.c
@@ -355,6 +355,9 @@ SYSCALL_DEFINE4(fallocate, int, fd, int, mode, loff_t, offset, loff_t, len)
 	return error;
 }

+#ifdef CONFIG_KSU
+extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
+			        int *flags);
+#endif
+
 /*
  * access() needs to use the real uid/gid, not the effective uid/gid.
  * We do this by temporarily clearing all FS-related capabilities and
@@ -370,6 +373,8 @@ SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 	int res;
 	unsigned int lookup_flags = LOOKUP_FOLLOW;
+   #ifdef CONFIG_KSU
+	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
+   #endif
+
 	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
 		return -EINVAL;
```

### Safe Mode {#safemode}
It's strongly recommended to enable this feature, it's very useful for preventing bootloops!
To enable ReSukiSU s built-in Safe Mode, you should modify the `input_handle_event` function in `drivers/input/input.c`:

```diff

index 45306f9ef247..815091ebfca4 100755

:::tip
It's strongly recommended to enable this feature, it's very useful for preventing bootloops!
:::
--- a/drivers/input/input.c
+++ b/drivers/input/input.c
@@ -367,10 +367,13 @@ static int input_get_disposition(struct input_dev *dev,
 	return disposition;
 }

+#ifdef CONFIG_KSU
+extern bool ksu_input_hook __read_mostly;
+extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);
+#endif
+
 static void input_handle_event(struct input_dev *dev,
 			       unsigned int type, unsigned int code, int value)
 {
	int disposition = input_get_disposition(dev, type, code, &value);
+   #ifdef CONFIG_KSU
+	if (unlikely(ksu_input_hook))
+		ksu_handle_input_handle_event(&type, &code, &value);
+   #endif
 
 	if (disposition != INPUT_IGNORE_EVENT && type != EV_SYN)
 		add_input_randomness(type, code, value);
```

### setresuid {#setresuid}

::: tip
Since Kernel 6.8,We required you add this patch.if not,system cannot booted.

Of course,this part will be checked,if your kernel >= 6.8 and not patched this hook,building will fail!
:::

```diff
diff --git a/kernel/sys.c b/kernel/sys.c
index 4a87dc5fa..aac25df8c 100644
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -679,6 +679,10 @@ SYSCALL_DEFINE1(setuid, uid_t, uid)
 }
 
 
+#ifdef CONFIG_KSU
+extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);
+#endif
+
 /*
  * This function implements a generic ability to update ruid, euid,
  * and suid.  This allows you to implement the 4.4 compatible seteuid().
@@ -692,6 +696,10 @@ long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
 	kuid_t kruid, keuid, ksuid;
 	bool ruid_new, euid_new, suid_new;
 
+#ifdef CONFIG_KSU
+	ksu_handle_setresuid(ruid, euid, suid);
+#endif
+
 	kruid = make_kuid(ns, ruid);
 	keuid = make_kuid(ns, euid);
 	ksuid = make_kuid(ns, suid);
```

### path_umount {#how-to-backport-path-umount}

::: info Notes
This is an optional patch，you don't need to apply this one.
:::

You can make the "Umount modules" feature work on pre-GKI kernels by manually backporting `path_umount` from 5.9. You can use this patch as reference:

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

## Reference Patches

|地址|说明|
|--|--|
|[`rksuorg/kernel_patches`](https://github.com/rksuorg/kernel_patches)|based on [official manual](manual-hooks.md#manual-hooks) |
|[`WildKernels/kernel_patches`](https://github.com/WildKernels/kernel_patches/tree/main/next)|based on [scope-minimized-hooks](manual-hooks.md#scope-minimized-hooks) 的补丁|