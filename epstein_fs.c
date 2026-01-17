#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/stddef.h>
#include <linux/random.h>
#include <linux/limits.h>
#include <linux/tty.h>
#include <asm/ptrace.h>

#define MAX_DIRENT_BYTES (32 * 1024)
#define REDACTION_GLYPH "\xE2\x96\x88"
#define REDACTION_GLYPH_LEN 3

static bool filter_require_tty = true; // if process has a controlling tty
static bool filter_parent_comm = true; // filter by parent to prevent cluttering 'em ring buffers

static const char * const parent_comm_allowlist[] = {
	"bash",
	"zsh",
	"fish",
	"sh",
}; //u can edit those

static bool redact_names = true; //set to false if you dont want rootkitish behavior
static u32 redact_probability_percent = 65; //whatever works best for u bestie

//nerd shit
static u8 redact_slice_min = 2;
static u8 redact_slice_max = 6;

static const char * const protected_entries[] = {
	".",
	"..",
	"",
};

struct getdents_ctx {
	int fd;
	struct linux_dirent64 __user *dirent;
	unsigned int count;
	bool should_redact;
};

static const char * const getdents_symbols[] = {
	"__arm64_sys_getdents64",
	"__se_sys_getdents64",
	"__do_sys_getdents64",
	"sys_getdents64",
};

static const char *active_symbol;

static bool task_has_tty(const struct task_struct *task)
{
	struct tty_struct *tty;
	bool ok = false;

	if (!task || !task->signal)
		return false;

	rcu_read_lock();
	tty = rcu_dereference(task->signal->tty);
	if (tty)
		ok = true;
	rcu_read_unlock();

	return ok;
}

static bool parent_comm_allowed(const struct task_struct *task)
{
	const struct task_struct *parent;
	size_t i;

	if (!task)
		return false;

	rcu_read_lock();
	parent = rcu_dereference(task->real_parent);
	if (!parent) {
		rcu_read_unlock();
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(parent_comm_allowlist); i++) {
		if (strncmp(parent->comm, parent_comm_allowlist[i],
			    TASK_COMM_LEN) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	return false;
}

static bool symbol_uses_pt_regs(const char *symbol)
{
	return symbol && strcmp(symbol, "__arm64_sys_getdents64") == 0;
}

static u32 rand_u32_bounded(u32 max)
{
	if (!max)
		return 0;
	return get_random_u32() % max;
}

static bool is_protected_entry(const char *name, size_t name_len)
{
	size_t i;
	
	for (i = 0; i < ARRAY_SIZE(protected_entries); i++) {
		if (strncmp(name, protected_entries[i], name_len) == 0 &&
		    strlen(protected_entries[i]) == name_len) {
			return true;
		}
	}

	if (name_len > 0 && name[0] == '.')
		return true;

	return false;
}

static size_t calculate_redacted_size(const char *name, size_t name_len)
{
	size_t use_len = min_t(size_t, name_len, NAME_MAX);
	size_t start, slice_len;
	u32 range;

	if (!redact_names || use_len == 0)
		return use_len;

	if (is_protected_entry(name, use_len))
		return use_len;

	if (rand_u32_bounded(100) >= redact_probability_percent)
		return use_len;

	if (redact_slice_min == 0 || redact_slice_min > redact_slice_max)
		return use_len;

	range = redact_slice_max - redact_slice_min + 1;
	slice_len = redact_slice_min + rand_u32_bounded(range);
	if (slice_len > use_len)
		slice_len = use_len;

	if (use_len > slice_len)
		start = rand_u32_bounded(use_len - slice_len + 1);
	else
		start = 0;

	return use_len + (slice_len * (REDACTION_GLYPH_LEN - 1));
}

static int redact_name(const char *src, size_t src_len, char *dst, size_t dst_len)
{
	size_t use_len = min_t(size_t, src_len, NAME_MAX);
	size_t start, slice_len, suffix_len, pos = 0;
	u32 range;
	u8 i;

	if (!redact_names || use_len == 0) {
		if (use_len < dst_len) {
			memcpy(dst, src, use_len);
			if (use_len < dst_len)
				dst[use_len] = '\0';
			return use_len;
		}
		return 0;
	}

	if (is_protected_entry(src, use_len)) {
		if (use_len < dst_len) {
			memcpy(dst, src, use_len);
			if (use_len < dst_len)
				dst[use_len] = '\0';
			return use_len;
		}
		return 0;
	}

	if (rand_u32_bounded(100) >= redact_probability_percent) {
		if (use_len < dst_len) {
			memcpy(dst, src, use_len);
			if (use_len < dst_len)
				dst[use_len] = '\0';
			return use_len;
		}
		return 0;
	}

	if (redact_slice_min == 0 || redact_slice_min > redact_slice_max) {
		if (use_len < dst_len) {
			memcpy(dst, src, use_len);
			if (use_len < dst_len)
				dst[use_len] = '\0';
			return use_len;
		}
		return 0;
	}

	range = redact_slice_max - redact_slice_min + 1;
	slice_len = redact_slice_min + rand_u32_bounded(range);
	if (slice_len > use_len)
		slice_len = use_len;

	start = 0;
	if (use_len > slice_len)
		start = rand_u32_bounded(use_len - slice_len + 1);

	size_t needed = start + (slice_len * REDACTION_GLYPH_LEN) + (use_len - (start + slice_len));
	if (needed >= dst_len)
		return use_len;

	if (start > 0) {
		memcpy(dst + pos, src, start);
		pos += start;
	}

	for (i = 0; i < slice_len; i++) {
		memcpy(dst + pos, REDACTION_GLYPH, REDACTION_GLYPH_LEN);
		pos += REDACTION_GLYPH_LEN;
	}

	suffix_len = use_len - (start + slice_len);
	if (suffix_len > 0) {
		memcpy(dst + pos, src + start + slice_len, suffix_len);
		pos += suffix_len;
	}

	dst[pos] = '\0';
	return pos;
}

static int getdents_entry_handler(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct getdents_ctx *ctx = (struct getdents_ctx *)ri->data;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;

	if (symbol_uses_pt_regs(active_symbol)) {
		struct pt_regs *syscall_regs;

		syscall_regs = (struct pt_regs *)regs_get_kernel_argument(regs, 0);
		arg0 = regs_get_kernel_argument(syscall_regs, 0);
		arg1 = regs_get_kernel_argument(syscall_regs, 1);
		arg2 = regs_get_kernel_argument(syscall_regs, 2);
	} else {
		arg0 = regs_get_kernel_argument(regs, 0);
		arg1 = regs_get_kernel_argument(regs, 1);
		arg2 = regs_get_kernel_argument(regs, 2);
	}

	ctx->fd = (int)arg0;
	ctx->dirent = (struct linux_dirent64 __user *)arg1;
	ctx->count = (unsigned int)arg2;
	ctx->should_redact = false;

	if (filter_require_tty && !task_has_tty(current))
		return 0;
	if (filter_parent_comm && !parent_comm_allowed(current))
		return 0;

	ctx->should_redact = true;
	return 0;
}

static int getdents_ret_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct getdents_ctx *ctx = (struct getdents_ctx *)ri->data;
	long ret = regs_return_value(regs);
	size_t bytes, offset;
	const size_t header_size = offsetof(struct linux_dirent64, d_name);
	void *kbuf = NULL;
	void *new_kbuf = NULL;
	size_t new_bytes = 0;
	bool modified = false;
	long new_ret = ret;

	if (ret <= 0 || !ctx->dirent)
		return 0;

	if (!ctx->should_redact) {
		return 0;
	}

	bytes = (size_t)ret;
	if (bytes > ctx->count)
		bytes = ctx->count;
	if (bytes > MAX_DIRENT_BYTES) {
		pr_info("pid=%d comm=%s fd=%d bytes=%zu skipped (too large)\n",
			current->pid, current->comm, ctx->fd, bytes);
		return 0;
	}

	kbuf = kmalloc(bytes, GFP_ATOMIC);
	if (!kbuf)
		return 0;

	if (copy_from_user(kbuf, ctx->dirent, bytes)) {
		kfree(kbuf);
		return 0;
	}

	pr_info("pid=%d comm=%s fd=%d bytes=%zu (processing for redaction)\n",
		current->pid, current->comm, ctx->fd, bytes);

	new_bytes = 0;
	for (offset = 0; offset + header_size + 1 <= bytes; ) {
		struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + offset);
		size_t reclen = d->d_reclen;
		size_t name_offset = offset + header_size;
		size_t name_max_len;
		size_t name_len;

		if (reclen < header_size + 1)
			break;
		if (offset + reclen > bytes)
			break;

		name_max_len = reclen - header_size;
		name_len = strnlen((char *)kbuf + name_offset, name_max_len);
		
		size_t new_name_len = calculate_redacted_size((char *)kbuf + name_offset, name_len);
		size_t new_reclen = header_size + new_name_len + 1;

		new_reclen = (new_reclen + 7) & ~7;

		new_bytes += new_reclen;
		offset += reclen;
	}

	offset = 0;

	if (new_bytes == 0 || new_bytes > ctx->count) {
		for (offset = 0; offset + header_size + 1 <= bytes; ) {
			struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + offset);
			size_t reclen = d->d_reclen;
			size_t name_offset = offset + header_size;
			size_t name_max_len;
			size_t name_len;

			if (reclen < header_size + 1)
				break;
			if (offset + reclen > bytes)
				break;

			name_max_len = reclen - header_size;
			name_len = strnlen((char *)kbuf + name_offset, name_max_len);
			
			pr_info("  name=%.*s ino=%llu type=%u\n",
				(int)name_len, (char *)kbuf + name_offset,
				(unsigned long long)d->d_ino,
				(unsigned int)d->d_type);

			offset += reclen;
		}

		kfree(kbuf);
		return 0;
	}

	new_kbuf = kmalloc(new_bytes, GFP_ATOMIC);
	if (!new_kbuf) {
		kfree(kbuf);
		return 0;
	}

	offset = 0;
	size_t new_offset = 0;
	while (offset + header_size + 1 <= bytes && new_kbuf) {
		struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + offset);
		struct linux_dirent64 *new_d = (struct linux_dirent64 *)(new_kbuf + new_offset);
		size_t reclen = d->d_reclen;
		size_t name_offset = offset + header_size;
		size_t name_max_len;
		size_t name_len;

		if (reclen < header_size + 1)
			break;
		if (offset + reclen > bytes)
			break;

		name_max_len = reclen - header_size;
		name_len = strnlen((char *)kbuf + name_offset, name_max_len);
		
		char redacted[NAME_MAX * REDACTION_GLYPH_LEN + 1];
		int redacted_len = redact_name((char *)kbuf + name_offset, name_len,
					      redacted, sizeof(redacted));

		if (redacted_len > 0 && redacted_len != name_len) {
			size_t new_name_len = redacted_len;
			size_t new_reclen = header_size + new_name_len + 1;
			new_reclen = (new_reclen + 7) & ~7;

			if (new_offset + new_reclen > new_bytes ||
			    new_offset + new_reclen > ctx->count) {
				break;
			}

			memcpy(new_d, d, header_size);
			new_d->d_reclen = new_reclen;

			memcpy(new_d->d_name, redacted, redacted_len);
			new_d->d_name[redacted_len] = '\0';

			new_offset += new_reclen;
			modified = true;

			pr_info("  REDACTED: name=%.*s (was %.*s) ino=%llu type=%u\n",
				redacted_len, redacted,
				(int)name_len, (char *)kbuf + name_offset,
				(unsigned long long)d->d_ino,
				(unsigned int)d->d_type);
		} else {
			if (new_offset + reclen > new_bytes) {
				break;
			}

			memcpy(new_d, d, reclen);
			new_offset += reclen;

			pr_info("  name=%.*s ino=%llu type=%u\n",
				(int)name_len, (char *)kbuf + name_offset,
				(unsigned long long)d->d_ino,
				(unsigned int)d->d_type);
		}
		
		offset += reclen;
	}

	if (modified && new_kbuf) {
		new_ret = new_offset;
		if (copy_to_user(ctx->dirent, new_kbuf, new_offset)) {
			pr_warn("pid=%d comm=%s: failed to copy redacted data to userspace\n",
				current->pid, current->comm);
			new_ret = ret;
		} else {
			regs_set_return_value(regs, new_ret);
			pr_info("pid=%d comm=%s: redacted data propagated to userspace (new size=%zu)\n",
				current->pid, current->comm, new_offset);
		}
	}

	kfree(kbuf);
	if (new_kbuf)
		kfree(new_kbuf);

	return 0;
}

static struct kretprobe getdents_kretprobe = {
	.handler = getdents_ret_handler,
	.entry_handler = getdents_entry_handler,
	.data_size = sizeof(struct getdents_ctx),
	.maxactive = 64,
};

static int __init epstein_fs_init(void)
{
	int ret = -ENOENT;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(getdents_symbols); i++) {
		active_symbol = getdents_symbols[i];
		getdents_kretprobe.kp.symbol_name = getdents_symbols[i];
		ret = register_kretprobe(&getdents_kretprobe);
		if (ret == 0) {
			pr_info("registered kretprobe on %s\n", active_symbol);
			return 0;
		}
		active_symbol = NULL;
	}

	pr_err("failed to register kretprobe (%d)\n", ret);
	return ret;
}

static void __exit epstein_fs_exit(void)
{
	unregister_kretprobe(&getdents_kretprobe);
	pr_info("unregistered kretprobe from %s\n",
		active_symbol ? active_symbol : "unknown");
}

module_init(epstein_fs_init);
module_exit(epstein_fs_exit);

MODULE_LICENSE("GPL"); //who cares
MODULE_AUTHOR("Jen_(furrygem)");
MODULE_DESCRIPTION("epstein_fs getdents64 redaction via kretprobe");
